/**
 * @file PrecompElGamalPSIServer.cpp
 * 
 * @version 0.1
 *
 */
#include "PrecompElGamalPSIServer.hpp"

PrecompElGamalPSIServer::PrecompElGamalPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, HashTableParameter &htParams)
    : ElGamalPSIServer(dataIH, serverParams, htParams, protocolName())
{
    omp_set_num_threads(serverParams.numberOfThreads);
}

void PrecompElGamalPSIServer::runSetUpPhase()
{
    setUpElGamalPSI();

    // Build empty PIEs
    equalityTests = std::vector<std::shared_ptr<PrecompElGamalPIECollection>>(serverParams.numberOfThreads);
    for (size_t i = 0; i < serverParams.numberOfThreads; i++)
    {
        auto encNew = AddHomElGamalEnc(createDlogGroup());
        encNew.setKey(encryptor.getPublicKey());
        equalityTests[i] = make_shared<PrecompElGamalPIECollection>(std::move(encNew));
    }

    for (uint i = 0; i < serverHashTable->getNumberOfSimpleTables(); i++)
    {
        for (uint j = 0; j < serverHashTable->getEachSimpleTableSize(); j++)
        {
            uint collectionIndex = (i * serverHashTable->getEachSimpleTableSize() + j) / piesPerCollection;

            auto indexMatrix = receiveRandomIndexMatrix();
            equalityTests[collectionIndex]->addPIE(serverHashTable->hierarchicalCuckooTable[i][j], std::move(indexMatrix));
        }
    }

    precompThreadsPIE = vector<boost::thread *>(serverParams.numberOfThreads);
}

void precompTask(std::shared_ptr<PrecompElGamalPIECollection> &pieCollection)
{

    pieCollection->precompAll();

    // Clear index vectors after use
    //  delete compareElement;
    //  for(auto v1 : indexMatrix) {
    //      for(auto cEl : v1) {
    //          delete cEl;
    //      }

    //     v1.clear();
    // }
    // indexMatrix.clear();
}

void PrecompElGamalPSIServer::runOfflinePhase()
{

    // Insert Elements into Cuckoo table
    serverHashTable->insertAll(serverSet);

    for (uint i = 0; i < serverHashTable->getNumberOfSimpleTables(); i++)
    {

        for (uint j = 0; j < serverHashTable->getEachSimpleTableSize(); j++)
        {
            uint collectionIndex = (i * serverHashTable->getEachSimpleTableSize() + j) / piesPerCollection;
            uint pieNumber = (i * serverHashTable->getEachSimpleTableSize() + j);
            uint pieNumberInsideCollection = pieNumber % piesPerCollection;

            if (pieNumberInsideCollection == piesPerCollection - 1 || pieNumber == nPiesToHandle - 1)
            {
                // Start PIE thread
                auto &pieCollToRun = equalityTests[collectionIndex];
                precompThreadsPIE[collectionIndex] = new boost::thread(precompTask, pieCollToRun);
            }
        }
    }

    for (size_t collectionIndex = 0; collectionIndex < serverParams.numberOfThreads; collectionIndex++)
    {
        precompThreadsPIE[collectionIndex]->join();
    }
}

void threadTask(std::shared_ptr<PrecompElGamalPIECollection> &pieCollection)
{

    pieCollection->runAll();

    // Clear index vectors after use
    //  delete compareElement;
    //  for(auto v1 : indexMatrix) {
    //      for(auto cEl : v1) {
    //          delete cEl;
    //      }

    //     v1.clear();
    // }
    // indexMatrix.clear();
}

void PrecompElGamalPSIServer::runOnlinePhase()
{

    for (uint i = 0; i < serverHashTable->getNumberOfSimpleTables(); i++)
    {

        for (uint j = 0; j < serverHashTable->getEachSimpleTableSize(); j++)
        {
            uint pieNumber = (i * serverHashTable->getEachSimpleTableSize() + j);
            uint collectionIndex = pieNumber / piesPerCollection;
            uint pieNumberInsideCollection = pieNumber % piesPerCollection;

            // cout << "plain mbitset" << endl;
            boost::dynamic_bitset<byte> mbitset = receivePlainBitvector();

            // cout << "Receive compare element" << endl;
            AsymmetricCiphertext *compareElement = receiveMinusCompareElement();

            PrecompElGamalPIE &currentPIE = equalityTests[collectionIndex]->myPIEs[pieNumberInsideCollection];
            // cout << "Run PIE" << endl;
            currentPIE.setMinusCompareElement(compareElement);
            currentPIE.setBitVector(std::move(mbitset));

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
        for (PrecompElGamalPIE &pie : equalityTests[collectionIndex]->myPIEs)
        {
            sendResult(pie.getResultList());
        }
        delete threadsPIE[collectionIndex];
    }
}

vector<vector<AsymmetricCiphertext *>> PrecompElGamalPSIServer::receiveRandomIndexMatrix()
{
    vector<vector<AsymmetricCiphertext *>> indexMatrix = vector<vector<AsymmetricCiphertext *>>(htParams.numberOfCuckooHashFunctions,
                                                                                                vector<AsymmetricCiphertext *>(htParams.eachCuckooTableSize));
    for (uint outerIndex = 0; outerIndex < htParams.numberOfCuckooHashFunctions; outerIndex++)
    {
        for (uint64_t index = 0; index < htParams.eachCuckooTableSize; index++)
        {
            vector<unsigned char> cipherVector;
            channel->readWithSizeIntoVector(cipherVector);
            auto cipherText = encryptor.reconstructCiphertextPointer(cipherVector, false);
            indexMatrix[outerIndex][index] = cipherText;
        }
    }
    return indexMatrix;
}

boost::dynamic_bitset<byte> PrecompElGamalPSIServer::receivePlainBitvector()
{
    vector<unsigned char> cipherVector;
    channel->readWithSizeIntoVector(cipherVector);
    boost::dynamic_bitset<byte> mbitset(cipherVector.begin(), cipherVector.end());
    return mbitset;
}
