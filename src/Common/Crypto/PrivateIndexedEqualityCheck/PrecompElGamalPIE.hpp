/**
 * @file PrecompElGamalPIE.hpp
 * 
 * @version 0.1
 *
 *
 */
#pragma once
#include "src/Common/Crypto/AddHomElGamalEnc.hpp"
#include "HIPPIE.hpp"
#include "boost/dynamic_bitset.hpp"

class PrecompElGamalPIE : public HIPPIE
{

private:
    AddHomElGamalEnc &cryptor;
    vector<vector<vector<AsymmetricCiphertext *>>> negatedMessageMatrix;
    vector<vector<vector<AsymmetricCiphertext *>>> encryptedMessageMatrix;
    boost::dynamic_bitset<unsigned char> xorVector;
    vector<shared_ptr<AsymmetricCiphertext>> encryptedZeros;

public:
    PrecompElGamalPIE(AddHomElGamalEnc &cryptor, CuckooHashTable &ct);

    void precomp();

    void setBitVector(boost::dynamic_bitset<unsigned char> &&xorVector);

    void run() override;
};