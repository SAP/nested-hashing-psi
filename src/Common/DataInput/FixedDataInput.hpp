/**
 * @file FixedDataInput.cpp
 * 
 * @version 0.1
 */

#pragma once
#include "DataInputHandler.hpp"
/**
 * @brief Implementation of the DataInputHandler. Generates fixed elements for a given bit lengths.
 *        The size of the intersection can be defined beforehand.
 *
 *
 */
class FixedDataInput : public DataInputHandler
{

private:
    uint64_t bitSize;

    std::vector<biginteger> clientSet;
    std::vector<biginteger> serverSet;
    std::vector<biginteger> intersectionSet;

public:
    /**
     * @brief Construct a new Random Data Input object
     *
     * @param serverSetSize
     * @param clientSetSize
     * @param intersectionSize Size of the intersection, needs to be smaller than clientSetSize and serverSetSize
     * @param bitSize of generated elements
     */
    FixedDataInput(size_t serverSetSize, size_t clientSetSize, size_t intersectionSize, uint64_t bitSize);

    std::vector<biginteger> &getClientSet() override;
    std::vector<biginteger> &getServerSet() override;
    std::vector<biginteger> &getIntersectionSet() override;
};