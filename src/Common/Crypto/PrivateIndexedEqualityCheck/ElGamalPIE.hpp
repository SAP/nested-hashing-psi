/**
 * @file ElGamalPIE.hpp
 * 
 * @version 0.1
 *
 *
 */
#pragma once
#include "src/Common/Crypto/AddHomElGamalEnc.hpp"
#include "HIPPIE.hpp"

/**
 * @brief Class
 *
 */
class ElGamalPIE : public HIPPIE
{

private:
    AddHomElGamalEnc &cryptor;
    vector<vector<biginteger>> randomness;
    vector<shared_ptr<AsymmetricCiphertext>> encryptedZeros;
    bool precalcRandom;

public:
    ElGamalPIE(AddHomElGamalEnc &cryptor, CuckooHashTable &ct);

    void run() override;
};