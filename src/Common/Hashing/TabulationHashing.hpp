/**
 * @file TabulationHashing.cpp
 * 
 * @brief
 * @version 0.1
 *
 */
#pragma once
#include <random>
#include <vector>
#include "src/PSIConfigs.h"
/**
 * @brief Class that implements tabulation hashing
 *        The same class can be used for 'numberOfHashfunctions' many hash functions
 *        indicated in the hashWithIndicator hashfunction
 */
class TabulationHashing
{
private:
    size_t tParam = 16;
    size_t rParam = 8;
    size_t nHashfunctions;
    std::vector<std::vector<std::vector<uint64_t>>> tTable;

public:
    TabulationHashing(uint64_t seed = 342797434736, size_t numberOfHashfunctions = 3);

    /**
     * @brief Function to hash a biginteger corresponding to hashfunction indicated by hfInd.
     *        Uses plain biginteger instead of referenced because the input is manipulated during the hashing.
     * @param input to be hashed
     * @param hfInd indicates the i'th hash function
     * @return uint64_t hash value
     */
    uint64_t hashWithIndicator(biginteger input, uint hfInd);
};