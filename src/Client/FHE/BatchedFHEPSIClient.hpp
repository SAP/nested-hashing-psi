#pragma once
#include "../PSIClient.hpp"
#include "src/Common/Hashing/CuckooHashTable.hpp"
#include "src/Common/Crypto/PrivateIndexedEqualityCheck/PIECollection.hpp"
#include "src/Common/Parameter/HashTableParameter.hpp"

class BatchedFHEPSIClient : public PSIClient
{

private:
    const HashTableParameter &htParams;
    shared_ptr<CuckooHashTable> clientHashTable;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair;
    TabulationHashing hashfunction;
    vector<vector<lbcrypto::Ciphertext<FHEEncType>>> batchedEncryptedIndexMatrix;
    lbcrypto::Ciphertext<FHEEncType> encryptedMinusElements;
    vector<vector<int64_t>> batchedDecryptedResult;

    inline std::string protocolName()
    {
        return "BatchedFHE";
    }
    void sendEncryptedMinusElements();
    void sendIndexMatrix();
    void sendContextAndKeys();
    void receiveAndStoreResult();

public:
    BatchedFHEPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams);
    void runSetUpPhase() override;
    void runOfflinePhase() override;
    void runOnlinePhase() override;
};