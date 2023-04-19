/**
 * @file SimpleElGamalPSIServer.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "ElGamalPSIServer.hpp"

class SimpleElGamalPSIServer : public ElGamalPSIServer
{

private:
    vector<std::shared_ptr<ElGamalPIECollection>> equalityTests;

    vector<vector<AsymmetricCiphertext *>> receiveIndexMatrix();

    inline std::string protocolName()
    {
        return "Simple";
    }

public:
    SimpleElGamalPSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, HashTableParameter &htParams);
    void runSetUpPhase() override;
    void runOfflinePhase() override;
    void runOnlinePhase() override;
};