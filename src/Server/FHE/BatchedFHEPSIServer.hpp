/**
 * @file BatchedFHEPSIServer.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "../PSIServer.hpp"
#include "src/Common/Hashing/HierarchicalCuckooHashTable.hpp"
#include "src/Common/Crypto/PrivateIndexedEqualityCheck/BatchedFHEHIPPIE.hpp"
#include "src/Common/Parameter/HashTableParameter.hpp"
#include <chrono>

class BatchedFHEPSIServer : public PSIServer
{

private:
    const HashTableParameter &htParams;
    shared_ptr<HierarchicalCuckooHashTable> serverHashTable;
    std::shared_ptr<BatchedFHEHIPPIE> batchedEqualityTest;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext;
    lbcrypto::PublicKey<FHEEncType> pK;
    TabulationHashing hashfunction;

    void receiveAndSetContextAndKeys();
    vector<vector<lbcrypto::Ciphertext<FHEEncType>>> receiveIndexMatrix();
    lbcrypto::Ciphertext<FHEEncType> receiveEncryptedMinusElements();
    void sendResult(vector<lbcrypto::Ciphertext<FHEEncType>> &resultVector);
    inline std::string protocolName()
    {
        return "BatchedFHE";
    }

public:
    BatchedFHEPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, HashTableParameter &htParams);
    void runSetUpPhase() override;
    void runOfflinePhase() override;
    void runOnlinePhase() override;
};