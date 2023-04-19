/**
 * @file SimpleElGamalPSIClient.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "ElGamalPSIClient.hpp"
class SimpleElGamalPSIClient : public ElGamalPSIClient
{

private:
    // Stores the encrypted PIE index vectors from the offline phase.
    vector<vector<indexVectorType *>> encryptedCuckooIndexMatrices;

    indexVectorType *generateIndexMatrix(biginteger &element);
    void sendIndexMatrix(indexVectorType *indexMatrix);

    inline std::string protocolName()
    {
        return "SimpleElGamal";
    }

public:
    SimpleElGamalPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams);
    void runSetUpPhase() override;
    void runOfflinePhase() override;
    void runOnlinePhase() override;
};