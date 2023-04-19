/**
 * @file SimpleFHEPSIServer.cpp
 * 
 * @version 0.1
 *
 */
#include "SimpleFHEPSIServer.hpp"
#include "src/Common/DataInput/RandomDataInput.hpp"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

SimpleFHEPSIServer::SimpleFHEPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, HashTableParameter &htParams)
    : PSIServer(dataIH, serverParams, protocolName()), htParams(htParams)
{
    omp_set_num_threads(1); // Always use one thread for omp
}

void SimpleFHEPSIServer::receiveAndSetContextAndKeys()
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

    // Deserialize Sum Keys

    vector<unsigned char> sKVector;
    channel->readWithSizeIntoVector(sKVector);
    auto sKStream = std::istringstream(std::string(sKVector.begin(), sKVector.end()));
    cryptoContext->DeserializeEvalSumKey(sKStream, defaultSerType);

#ifdef VERBOSE
    std::cout << "The sum keys have been deserialized. Size:" << sKVector.size() << std::endl;
#endif

    // Deserialize authomorphism keys

    vector<unsigned char> erVector;
    channel->readWithSizeIntoVector(erVector);
    auto erSS = std::istringstream(std::string(erVector.begin(), erVector.end()));
    cryptoContext->DeserializeEvalAutomorphismKey(erSS, defaultSerType);

#ifdef VERBOSE
    std::cout << "The automorphism keys have been deserialized. Size:" << erVector.size() << std::endl;
#endif
}

void SimpleFHEPSIServer::runSetUpPhase()
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
                                                               htParams.numberOfCuckooHashFunctions, htParams.simpleMultiTable, htParams.cuckooMultiTable, htParams.maxItemsPerPosition);

    nPiesToHandle = serverHashTable->getNumberOfSimpleTables() * serverHashTable->getEachSimpleTableSize();

    if (nPiesToHandle % serverParams.numberOfThreads != 0)
    {
        throw invalid_argument("Error: Number of Threads does not divide number of PIEs");
    }
}
void SimpleFHEPSIServer::runOfflinePhase()
{

    // Insert Elements into Cuckoo table
    serverHashTable->insertAll(serverSet);

    piesPerCollection = nPiesToHandle / serverParams.numberOfThreads; // Rounds up

    threadsPIE = vector<boost::thread *>(serverParams.numberOfThreads);

    /** Build PIEs (WARNING currently need to do this after the cuckoo table has been inserted with items
     * because of item type conversion during PIE creation)
     */
    equalityTests = std::vector<std::shared_ptr<FHEHIPPIECollection>>(serverParams.numberOfThreads);
    for (size_t i = 0; i < equalityTests.size(); i++)
    {
        equalityTests[i] = make_shared<FHEHIPPIECollection>(cryptoContext, pK);
    }

    for (uint i = 0; i < serverHashTable->getNumberOfSimpleTables(); i++)
    {

        for (uint j = 0; j < serverHashTable->getEachSimpleTableSize(); j++)
        {
            uint collectionIndex = (i * serverHashTable->getEachSimpleTableSize() + j) / piesPerCollection;

            equalityTests[collectionIndex]->addPIE(serverHashTable->hierarchicalCuckooTable[i][j]);
        }
    }
}

void threadTask(std::shared_ptr<FHEHIPPIECollection> &pieCollection)
{
    pieCollection->runAll();
}

void SimpleFHEPSIServer::runOnlinePhase()
{

    for (uint i = 0; i < serverHashTable->getNumberOfSimpleTables(); i++)
    {
        for (uint j = 0; j < serverHashTable->getEachSimpleTableSize(); j++)
        {
            uint pieNumber = (i * serverHashTable->getEachSimpleTableSize() + j);
            uint collectionIndex = pieNumber / piesPerCollection;
            uint pieNumberInsideCollection = pieNumber % piesPerCollection;

            // cout << "Receive index matrix" << endl;
            vector<lbcrypto::Ciphertext<FHEEncType>> indexMatrix = receiveIndexMatrix();

            FHEHIPPIE &currentPIE = equalityTests[collectionIndex]->myPIEs[pieNumberInsideCollection];
            // cout << "Run PIE" << endl;
            currentPIE.setIndex(std::move(indexMatrix));

            if (pieNumberInsideCollection == piesPerCollection - 1 || pieNumber == nPiesToHandle - 1)
            {
                // Start PIE thread
                auto &pieCollToRun = equalityTests[collectionIndex];
                threadsPIE[collectionIndex] = new boost::thread(threadTask, pieCollToRun);
            }
        }
    }

    for (size_t collectionIndex = 0; collectionIndex < serverParams.numberOfThreads; collectionIndex++)
    {
        threadsPIE[collectionIndex]->join();
        for (FHEHIPPIE &pie : equalityTests[collectionIndex]->myPIEs)
        {
            sendResult(pie.getResultList());
        }
        delete threadsPIE[collectionIndex];
    }
}

vector<lbcrypto::Ciphertext<FHEEncType>> SimpleFHEPSIServer::receiveIndexMatrix()
{
    vector<lbcrypto::Ciphertext<FHEEncType>> indexMatrix(htParams.numberOfCuckooHashFunctions);
    for (uint outerIndex = 0; outerIndex < htParams.numberOfCuckooHashFunctions; outerIndex++)
    {
        lbcrypto::Ciphertext<FHEEncType> ciphertext;
        vector<unsigned char> cipherVector;
        channel->readWithSizeIntoVector(cipherVector);
        auto ctSS = std::istringstream(std::string(cipherVector.begin(), cipherVector.end()));
        lbcrypto::Serial::Deserialize(ciphertext, ctSS, defaultSerType);
        indexMatrix[outerIndex] = ciphertext;
    }
    return indexMatrix;
}

void SimpleFHEPSIServer::sendResult(vector<lbcrypto::Ciphertext<FHEEncType>> &resultVector)
{

    for (size_t i = 0; i < resultVector.size(); i++)
    {
        auto cSerStream = std::ostringstream();
        lbcrypto::Serial::Serialize(resultVector[i], cSerStream, defaultSerType);
        channel->writeWithSize(cSerStream.str());
    }
}
