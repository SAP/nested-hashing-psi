/**
 * @file SimpleElGamalPSIServer.cpp
 * 
 * @version 0.1
 *
 */
#include "SimpleElGamalPSIServer.hpp"

SimpleElGamalPSIServer::SimpleElGamalPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, HashTableParameter &htParams)
    : ElGamalPSIServer(dataIH, serverParams, htParams, protocolName())
{
    omp_set_num_threads(serverParams.numberOfThreads);
}

void SimpleElGamalPSIServer::runSetUpPhase()
{
    setUpElGamalPSI();

    // Build PIEs
    equalityTests = std::vector<std::shared_ptr<ElGamalPIECollection>>(serverParams.numberOfThreads);
    for (size_t i = 0; i < serverParams.numberOfThreads; i++)
    {
        auto encNew = AddHomElGamalEnc(createDlogGroup());
        encNew.setKey(encryptor.getPublicKey());
        equalityTests[i] = make_shared<ElGamalPIECollection>(std::move(encNew));
    }
}

void SimpleElGamalPSIServer::runOfflinePhase()
{
    // Insert Elements into Cuckoo table
    serverHashTable->insertAll(serverSet);

    for (uint i = 0; i < serverHashTable->getNumberOfSimpleTables(); i++)
    {

        for (uint j = 0; j < serverHashTable->getEachSimpleTableSize(); j++)
        {
            uint collectionIndex = (i * serverHashTable->getEachSimpleTableSize() + j) / piesPerCollection;

            equalityTests[collectionIndex]->addPIE(serverHashTable->hierarchicalCuckooTable[i][j]);
        }
    }
}

void threadTask(std::shared_ptr<ElGamalPIECollection> &pieCollection)
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

void SimpleElGamalPSIServer::runOnlinePhase()
{

    for (uint i = 0; i < serverHashTable->getNumberOfSimpleTables(); i++)
    {

        for (uint j = 0; j < serverHashTable->getEachSimpleTableSize(); j++)
        {
            uint pieNumber = (i * serverHashTable->getEachSimpleTableSize() + j);
            uint collectionIndex = pieNumber / piesPerCollection;
            uint pieNumberInsideCollection = pieNumber % piesPerCollection;

            // cout << "Receive index matrix" << endl;
            vector<vector<AsymmetricCiphertext *>> indexMatrix = receiveIndexMatrix();

            // cout << "Receive compare element" << endl;
            AsymmetricCiphertext *minusCompareElement = receiveMinusCompareElement();

            ElGamalPIE &currentPIE = equalityTests[collectionIndex]->myPIEs[pieNumberInsideCollection];
            // cout << "Run PIE" << endl;
            currentPIE.setIndexAndMinusCompareElement(std::move(indexMatrix), minusCompareElement);

            if (pieNumberInsideCollection == piesPerCollection - 1 || pieNumber == nPiesToHandle - 1)
            {
                // Start PIE thread
                auto &pieCollToRun = equalityTests[collectionIndex];
                threadsPIE[collectionIndex] = new boost::thread(threadTask, pieCollToRun);
            }
        }
    }

    for (size_t collectionIndex = 0; collectionIndex < threadsPIE.size(); collectionIndex++)
    {
        threadsPIE[collectionIndex]->join();
        for (ElGamalPIE &pie : equalityTests[collectionIndex]->myPIEs)
        {
            sendResult(pie.getResultList());
        }
        delete threadsPIE[collectionIndex];
    }
}

vector<vector<AsymmetricCiphertext *>> SimpleElGamalPSIServer::receiveIndexMatrix()
{
    vector<vector<AsymmetricCiphertext *>> indexMatrix = vector<vector<AsymmetricCiphertext *>>(htParams.numberOfCuckooHashFunctions,
                                                                                                vector<AsymmetricCiphertext *>(htParams.eachCuckooTableSize));
    for (uint outerIndex = 0; outerIndex < htParams.numberOfCuckooHashFunctions; outerIndex++)
    {
        for (size_t index = 0; index < htParams.eachCuckooTableSize; index++)
        {
            vector<unsigned char> cipherVector;
            channel->readWithSizeIntoVector(cipherVector);
            auto cipherText = encryptor.reconstructCiphertextPointer(cipherVector, false);
            indexMatrix[outerIndex][index] = cipherText;
        }
    }
    return indexMatrix;
}
