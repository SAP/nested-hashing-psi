/**
 * @file HashUtils.cpp
 * 
 * @brief
 * @version 0.1
 *
 *
 */
#include "HashUtils.hpp"

/**
 * @brief Calculates the hash of value corresponding to hfInd and hashfunction
 *
 * @param hashfunction
 * @param value
 * @param hfInd hash function identifier number
 * @return uint64_t
 */
uint64_t calculateHash(TabulationHashing &hashfunction,
                       biginteger value, uint hfInd)
{
    return hashfunction.hashWithIndicator(value, hfInd);
}

/**
 * @brief Calculates the hash index (modulo tableSize) of value corresponding to hfInd and hashfunction
 *
 * @param hashfunction
 * @param value
 * @param hfInd hash function identifier number
 * @param tableSize
 * @return uint_fast64_t
 */
uint_fast64_t calculateHashIndex(TabulationHashing &hashfunction, biginteger value, uint hfInd, uint tableSize)
{
    return calculateHash(hashfunction, value, hfInd) % tableSize;
}

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
                                                   vector<biginteger> &elements, uint hfInd, uint tableSize)
{

    vector<vector<biginteger>> simpleTable(tableSize);
    for (biginteger currentElement : elements)
    {
        uint_fast64_t hashIndex = calculateHashIndex(hashfunction, currentElement, hfInd, tableSize);
        simpleTable[hashIndex].push_back(currentElement);
    }
    return simpleTable;
}

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
                                                            uint tableSize, uint numberOfHashfunctions)
{

    vector<vector<biginteger>> simpleTable(tableSize);
    for (biginteger currentElement : elements)
    {
        for (uint i = startHashInd; i < numberOfHashfunctions + startHashInd; i++)
        {
            uint_fast64_t hashIndex = calculateHashIndex(hashfunction, currentElement, i, tableSize);
            simpleTable[hashIndex].push_back(currentElement);
        }
    }
    return simpleTable;
}

/**
 * @brief Creates a randomly shuffled array [1,..,size]
 *
 * @param size of the permutation vector
 * @param seed to generate the permutation based on a mersenne twister
 * @return vector<uint>
 */
vector<uint> createPermutationVector(size_t size, int seed)
{
    std::random_device rd;
    boost::random::mt19937 rng(rd());

    std::vector<uint> v(size);
    std::iota(std::begin(v), std::end(v), 0);
    std::shuffle(std::begin(v), std::end(v), rng);

    return v;
}

uint randomModRange(size_t size, boost::random::mt19937 &mt, boost::random::uniform_int_distribution<uint64_t> &randGen)
{
    return randGen(mt) % size;
}

/**
 * @brief Generates a random biginteger of the given bitSize using randGen(mt)
 *        Used to generate the random PSI input items
 * @param mt
 * @param randGen
 * @param bitSize
 * @return biginteger
 */
biginteger randomBiginteger(boost::random::mt19937 &mt, boost::random::uniform_int_distribution<uint64_t> &randGen, uint64_t bitSize)
{

    // If 64 does not divide bitSize
    biginteger randomBI = 0;
    uint64_t leftBitsCount = bitSize / 64;

    uint64_t restBits = bitSize % 64;
    if (restBits != 0)
    {

        uint64_t firstBitsMod = (1ULL << restBits);
        randomBI = (randGen(mt) % firstBitsMod);
    }

    while (leftBitsCount > 0)
    {
        randomBI = (randomBI << 64) ^ randGen(mt);
        leftBitsCount--;
    }

    return randomBI;
}
