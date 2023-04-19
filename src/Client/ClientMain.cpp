/**
 * @file ClientMain.cpp
 * 
 * @brief Main Executable for the client PSI protocol
 * @version 0.1
 *
 */
#include <iostream>
#include <vector>
#include <string>
#include "ElGamal/SimpleElGamalPSIClient.hpp"
#include "ElGamal/PrecompElGamalPSIClient.hpp"
#include "src/Common/DataInput/RandomDataInput.hpp"
#include "src/Common/DataInput/FixedDataInput.hpp"
#include "src/Common/Parameter/CLI.hpp"
#include "FHE/SimpleFHEPSIClient.hpp"
#include "FHE/BatchedFHEPSIClient.hpp"
#include <omp.h>

int main(int argc, char *argv[])
{
    omp_set_num_threads(1); // Always use one thread for omp
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

    PSIClient *psiClient;

    if (psiParams.fhe)
    {
        if (psiParams.batched)
        {
            psiClient = new BatchedFHEPSIClient(RDI, psiParams, htParams);
        }
        else
        {
            psiClient = new SimpleFHEPSIClient(RDI, psiParams, htParams);
        }
    }
    else
    {
        if (psiParams.precomp)
        {
            psiClient = new PrecompElGamalPSIClient(RDI, psiParams, htParams);
        }
        else
        {
            psiClient = new SimpleElGamalPSIClient(RDI, psiParams, htParams);
        }
    }

    psiClient->run();
}
