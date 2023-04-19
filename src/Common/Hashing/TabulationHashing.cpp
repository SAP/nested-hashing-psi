/**
 * @file TabulationHashing.cpp
 * 
 * @brief
 * @version 0.1
 *
 */
#include "TabulationHashing.hpp"
/**
 * @brief Construct a new Tabulation Hashing object.
 *        Generates and stores the random tables for the hashing.
 *
 * @param seed used for the randomness
 * @param numberOfHashfunctions indicates how many hash functions are usable later with this object
 */
TabulationHashing::TabulationHashing(uint64_t seed, size_t numberOfHashfunctions)
    : nHashfunctions(numberOfHashfunctions)
{

    tTable = std::vector<std::vector<std::vector<uint64_t>>>(nHashfunctions,
                                                             std::vector<std::vector<uint64_t>>(tParam, std::vector<uint64_t>(1UL << rParam)));
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint64_t> dis;

    for (size_t h = 0; h < tTable.size(); h++)
    {
        for (size_t i = 0; i < tTable[h].size(); i++)
        {
            for (size_t j = 0; j < tTable[h][i].size(); j++)
            {

                tTable[h][i][j] = dis(gen);
            }
        }
    }
}

/**
 * @brief Function to hash a biginteger corresponding to hashfunction indicated by hfInd.
 *        Uses plain biginteger instead of referenced because the input is manipulated during the hashing.
 * @param input to be hashed
 * @param hfInd indicates the i'th hash function
 * @return uint64_t hash value
 */
uint64_t TabulationHashing::hashWithIndicator(biginteger input, uint hfInd)
{
    uint64_t res = 0;
    for (size_t i = 0; i < tParam; i++)
    {
        res ^= tTable[hfInd][i][(unsigned char)(input)];
        input = input >> 8;
    }
    return res;
}