/**
 * @file HashUtils.hpp
 * 
 * @brief Header file that defines several useful helper functions using hashing.
 * @version 0.1
 *
 *
 */
#pragma once
#include "TabulationHashing.hpp"
#include "boost/random.hpp"

/**
 * @brief Calculates the hash of value corresponding to hfInd and hashfunction
 *
 * @param hashfunction
 * @param value
 * @param hfInd hash function identifier number
 * @return uint64_t
 */
uint64_t calculateHash(TabulationHashing &hashfunction, biginteger value, uint hfInd);

/**
 * @brief Calculates the hash index (modulo tableSize) of value corresponding to hfInd and hashfunction
 *
 * @param hashfunction
 * @param value
 * @param hfInd hash function identifier number
 * @param tableSize
 * @return uint_fast64_t
 */
uint_fast64_t calculateHashIndex(TabulationHashing &hashfunction,
                                 biginteger value, uint hfInd, uint tableSize);

/**
 * @brief Function returns a (tableSize) dimensional hashtable table for elements
 * correspoding to the hashfunction and identifier.
 * @param hashfunction
 * @param elements
 * @param hfInd
 * @param tableSize
 * @return vector<vector<biginteger>> multiSimpleTable
 */
vector<vector<biginteger>> generateSimpleHashTable(TabulationHashing &hashfunction,
                                                   vector<biginteger> &elements, uint hfInd, uint tableSize);

/**
 * @brief Function returns a (tableSize) dimensional hashtable table for elements
 * correspoding to the hashfunction with different hash identifier.
 * @param hashfunction
 * @param elements
 * @param startHashInd
 * @param tableSize
 * @param numberOfHashfunctions
 * @return vector<vector<biginteger>> multiSimpleTable
 */
vector<vector<biginteger>> generateMultiHashSimpleHashTable(TabulationHashing &hashfunction,
                                                            vector<biginteger> &elements, uint startHashInd,
                                                            uint tableSize, uint numberOfHashfunctions);
/**
 * @brief Compresses an byte vector to an uint by rotate and xor
 *
 */
static inline uint_fast64_t compressByteVectorToUint(vector<byte> input)
{
    // Compress output to integer
    uint_fast64_t outindex;
    for (byte b : input)
    {
        // Rotate

        outindex = (outindex << CHAR_BIT) ^ (outindex >> ((sizeof(uint_fast64_t) - 1) * CHAR_BIT));
        outindex = outindex ^ b;
    }
    return outindex;
}
/**
 * @brief Creates a randomly shuffled array [1,..,size]
 *
 * @param size of the permutation vector
 * @param seed to generate the permutation based on a mersenne twister
 * @return vector<uint>
 */
vector<uint> createPermutationVector(size_t size, int seed = 123456789);

uint randomModRange(size_t size, boost::random::mt19937 &mt, boost::random::uniform_int_distribution<uint64_t> &randGen);

/**
 * @brief Generates a random biginteger of the given bitSize using randGen(mt)
 *        Used to generate the random PSI input items
 * @param mt
 * @param randGen
 * @param bitSize
 * @return biginteger
 */
biginteger randomBiginteger(boost::random::mt19937 &mt, boost::random::uniform_int_distribution<uint64_t> &randGen, uint64_t bitSize = 128);