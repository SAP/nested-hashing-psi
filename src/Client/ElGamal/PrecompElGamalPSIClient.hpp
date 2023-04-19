/**
 * @file PrecompElGamalPSIClient.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "ElGamalPSIClient.hpp"

class PrecompElGamalPSIClient : public ElGamalPSIClient
{

private:
    // Pseudo Random Number Generator to create random bitvector and later reuse it without storing a large state
    PrgFromOpenSSLAES prg;

    // Secret Key (Seed) for Pseudo Random Number Generator
    SecretKey prgSecretKey;

    void createAndSendPlainBitvector(biginteger &element);
    void createAndSendRandomIndexMatrix();

    inline std::string protocolName()
    {
        return "PrecompElGamal";
    }

public:
    PrecompElGamalPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams);
    void runSetUpPhase() override;
    void runOfflinePhase() override;
    void runOnlinePhase() override;
};