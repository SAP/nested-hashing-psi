#pragma once
#include "infra/Common.hpp" //for correct uint64_t definitions, etc.

/**
 * @brief Struct to structure all parameters for psi
 *
 */
struct PSIParameter
{
    const size_t serverSetSize;
    const size_t clientSetSize;
    const size_t intersectionSetSize;
    const uint64_t hashSeed;
    const uint64_t itemSeed;
    const std::string ip;
    const int port;
    const bool verbose;
    const bool exportPerformance;
    size_t numberOfThreads;
    const bool precomp;
    const bool fhe;
    const uint64_t bitSize;
    const std::string curveName;
    const bool bgv;
    const bool batched;

    PSIParameter(size_t serverSetSize,
                 size_t clientSetSize,
                 size_t intersectionSetSize,
                 uint64_t hashSeed,
                 uint64_t itemSeed,
                 std::string ip,
                 int port,
                 bool verbose,
                 bool exportPerformance,
                 size_t numberOfThreads,
                 bool precomp,
                 bool fhe,
                 uint64_t bitSize,
                 std::string curveName,
                 bool bgv,
                 bool batched) : serverSetSize(serverSetSize),
                                 clientSetSize(clientSetSize),
                                 intersectionSetSize(intersectionSetSize),
                                 hashSeed(hashSeed),
                                 itemSeed(itemSeed),
                                 ip(ip),
                                 port(port),
                                 verbose(verbose),
                                 exportPerformance(exportPerformance),
                                 numberOfThreads(numberOfThreads),
                                 precomp(precomp),
                                 fhe(fhe),
                                 bitSize(bitSize),
                                 curveName(curveName),
                                 bgv(bgv),
                                 batched(batched)
    {
    }
};