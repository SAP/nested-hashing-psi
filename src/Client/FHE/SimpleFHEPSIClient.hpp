/**
 * @file SimpleFHEPSIClient.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "../PSIClient.hpp"
#include "src/Common/Hashing/CuckooHashTable.hpp"
#include "src/Common/Crypto/PrivateIndexedEqualityCheck/PIECollection.hpp"
#include "src/Common/Parameter/HashTableParameter.hpp"

typedef vector<lbcrypto::Ciphertext<FHEEncType>> indexFHEVectorType; // different to indexVectorType because of different framework and packing

class SimpleFHEPSIClient : public PSIClient
{

private:
    const HashTableParameter &htParams;
    shared_ptr<CuckooHashTable> clientHashTable;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair;
    TabulationHashing hashfunction;
    vector<vector<indexFHEVectorType *>> encryptedCuckooIndexMatrices;
    int resultSize;

    inline std::string protocolName()
    {
        return "SimpleFHE";
    }

    indexFHEVectorType *generateIndexMatrix(biginteger &element);
    void sendIndexMatrix(indexFHEVectorType *indexMatrix);
    void sendContextAndKeys();
    bool receiveResult();

public:
    SimpleFHEPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams);
    void runSetUpPhase() override;
    void runOfflinePhase() override;
    void runOnlinePhase() override;
};