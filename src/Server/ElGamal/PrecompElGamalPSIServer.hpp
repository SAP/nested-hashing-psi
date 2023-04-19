/**
 * @file PrecompElGamalPSIServer.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "ElGamalPSIServer.hpp"

class PrecompElGamalPSIServer : public ElGamalPSIServer
{

private:
    vector<vector<AsymmetricCiphertext *>> randomIndexMatrix;
    vector<std::shared_ptr<PrecompElGamalPIECollection>> equalityTests;
    vector<boost::thread *> precompThreadsPIE;

    vector<vector<AsymmetricCiphertext *>> receiveRandomIndexMatrix();
    boost::dynamic_bitset<byte> receivePlainBitvector();

    inline std::string protocolName()
    {
        return "Precomp";
    }

public:
    PrecompElGamalPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, HashTableParameter &htParams);
    void runSetUpPhase() override;
    void runOfflinePhase() override;
    void runOnlinePhase() override;
};