/**
 * @file ServerMain.cpp
 * 
 * @version 0.1
 *
 */
#include <iostream>
#include <vector>
#include <string>
#include "ElGamal/SimpleElGamalPSIServer.hpp"
#include "ElGamal/PrecompElGamalPSIServer.hpp"
#include "FHE/SimpleFHEPSIServer.hpp"
#include "FHE/BatchedFHEPSIServer.hpp"
#include "src/Common/DataInput/RandomDataInput.hpp"
#include "src/Common/DataInput/FixedDataInput.hpp"
#include "src/Common/Parameter/CLI.hpp"
#include <omp.h>

int main(int argc, char *argv[])
{

    pair<bool, pair<PSIParameter, HashTableParameter>> paramPair = readParameters(argc, argv);

    if (paramPair.first == false)
    {
        return 1;
    }

    PSIParameter &psiParams = paramPair.second.first;

    HashTableParameter &htParams = paramPair.second.second;
    RandomDataInput RDI(psiParams.serverSetSize, psiParams.clientSetSize,
                        psiParams.intersectionSetSize, psiParams.itemSeed, psiParams.bitSize);
    //FixedDataInput RDI(psiParams.serverSetSize, psiParams.clientSetSize,
    //                   psiParams.intersectionSetSize, psiParams.bitSize);

    PSIServer *psiServer;

    if (psiParams.fhe)
    {
        if (psiParams.batched)
        {
            psiServer = new BatchedFHEPSIServer(RDI, psiParams, htParams);
        }
        else
        {
            psiServer = new SimpleFHEPSIServer(RDI, psiParams, htParams);
        }
    }
    else
    {
        if (psiParams.precomp)
        {
            psiServer = new PrecompElGamalPSIServer(RDI, psiParams, htParams);
        }
        else
        {
            psiServer = new SimpleElGamalPSIServer(RDI, psiParams, htParams);
        }
    }

    psiServer->run();
}
