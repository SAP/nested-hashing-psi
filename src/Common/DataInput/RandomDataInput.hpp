/**
 * @file RandomDataInput.cpp
 * 
 * @version 0.1
 */

#pragma once
#include "DataInputHandler.hpp"
/**
 * @brief Implementation of the DataInputHandler. Generates random elements for a fixed seed and bit lengths.
 *        The size of the intersection can be defined beforehand.
 * @todo For performance reasons, currently does not check if sets contain the same elements more than once.
 *       However, for larger bit length and smaller set sizes, the correctness holds with overwhelming probability.
 *
 */
class RandomDataInput : public DataInputHandler
{

private:
    // The seed to generate the server and intersection set (and such part of the client set),
    // directly corresponds to the setGenerationSeed plus this mask
    const uint64_t serverSeedDiff = (((uint64_t)1) << 32) + (1 << 16) + 1;
    uint64_t bitSize;
    boost::random::mt19937 mtClient; // twister used for client elements (which are not part of the server set)
    boost::random::mt19937 mtServer; // twister used for server elements and intersection elements
    boost::random::uniform_int_distribution<uint64_t> randGen;
    bool clientAndIntersectionSetGenerated = false; // marks if client and intersection set have already been sampled (used for lazy sampling of server set)
    bool serverSetGenerated = false;                // marks if set set has already been sampled (used for lazy sampling of client set)

    std::vector<biginteger> clientSet;
    std::vector<biginteger> serverSet;
    std::vector<biginteger> intersectionSet;

    // Could be implemented to void dummy elements or duplicates.
    inline bool isNotAllowed(biginteger &testValue);
    void generateClientAndIntersectionSet();
    void generateServerSet();

public:
    /**
     * @brief Construct a new Random Data Input object
     *
     * @param serverSetSize
     * @param clientSetSize
     * @param intersectionSize Size of the intersection, needs to be smaller than clientSetSize and serverSetSize
     * @param setGenerationSeed Seed to generate elements
     * @param bitSize of generated elements
     */
    RandomDataInput(size_t serverSetSize, size_t clientSetSize, size_t intersectionSize, uint64_t setGenerationSeed, uint64_t bitSize);

    std::vector<biginteger> &getClientSet() override;
    std::vector<biginteger> &getServerSet() override;
    std::vector<biginteger> &getIntersectionSet() override;
};