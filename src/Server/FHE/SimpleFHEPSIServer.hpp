/**
 * @file SimpleFHEPSIServer.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "../PSIServer.hpp"
#include "src/Common/Hashing/HierarchicalCuckooHashTable.hpp"
#include "src/Common/Crypto/PrivateIndexedEqualityCheck/PIECollection.hpp"
#include "src/Common/Parameter/HashTableParameter.hpp"

class SimpleFHEPSIServer : public PSIServer
{

private:
    const HashTableParameter &htParams;
    shared_ptr<HierarchicalCuckooHashTable> serverHashTable;
    vector<std::shared_ptr<FHEHIPPIECollection>> equalityTests;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext;
    lbcrypto::PublicKey<FHEEncType> pK;
    TabulationHashing hashfunction;
    vector<boost::thread *> threadsPIE;
    size_t nPiesToHandle;
    size_t piesPerCollection;

    void receiveAndSetContextAndKeys();
    vector<lbcrypto::Ciphertext<FHEEncType>> receiveIndexMatrix();
    void sendResult(vector<lbcrypto::Ciphertext<FHEEncType>> &resultVector);
    inline std::string protocolName()
    {
        return "SimpleFHE";
    }

public:
    SimpleFHEPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, HashTableParameter &htParams);
    void runSetUpPhase() override;
    void runOfflinePhase() override;
    void runOnlinePhase() override;
};