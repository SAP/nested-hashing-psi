/**
 * @file CuckooHashTable.hpp
 * 
 * @brief
 * @version 0.1
 *
 * Definition of the CuckooHashTable class.
 *
 */
#pragma once
#include "HashUtils.hpp"

/**
 * @brief Class to manage a (blocked) cuckoo hash table.
 *
 */
class CuckooHashTable
{

private:
    TabulationHashing &hashfunction;
    uint64_t eachTableSize;
    uint numberOfHashFunctions;
    uint startingHashId;
    uint64_t maxStashSize;
    bool multipleTables;          // Indicates if each hashfunction has its 'own' table
    uint64_t maxItemsPerPosition; // Used for blocked cuckoo hashing with multiple items per bin

    uint64_t numberOfElements;
    uint64_t numberOfRetries = 1000; // hyperparam with no need to be optimized
    uint64_t numberOfTables;

    boost::random::mt19937 mt;
    boost::random::uniform_int_distribution<uint64_t> randGen;

public:
    vector<vector<vector<biginteger>>> cuckooTable; // Raw table, [hfInd] x [binIndex] x [index]
    vector<biginteger> stash;                       // Raw stash of size stashSize

    /**
     * @brief Construct a new Cuckoo Hasher:: Cuckoo Hasher object
     *
     * @param hashfunction The hash function that will be used
     * @note Is used for all hash positions by adding different identifier to the hash input
     *
     * @param eachTableSize Size of each single hash table
     * @param numberOfHashFunctions Number of different hash function slots
     * @param numberOfRetries Max loop counter for insertion failures
     * @param multipleTables Cuckoo hashing variant
     */
    CuckooHashTable(TabulationHashing &hashfunction,
                    uint64_t eachTableSize,
                    uint numberOfHashFunctions = 2,
                    uint startingHashId = 0,
                    uint64_t maxStashSize = 0,
                    bool multipleTables = true,
                    uint64_t maxItemsPerPosition = 1);

    /**
     * @brief
     *
     * @param elements to insert
     */
    void insertAll(vector<biginteger> &elements);

    /**
     * @brief Function to insert a value into the cuckoo hash table
     *
     * @param value that should be inserted into the table
     */
    void insert(biginteger &value);

    /**
     * @brief Checks whether cuckoo table has element
     *
     * @param element
     * @return true
     * @return false element not in Cuckoo table
     */
    bool lookUp(biginteger &element);

    uint getNumberOfHashFunctions()
    {
        return numberOfHashFunctions;
    }

    uint getStartingHashIndex()
    {
        return startingHashId;
    }

    bool hasMultipleTables()
    {
        return multipleTables;
    }

    uint64_t getBinSize()
    {
        return maxItemsPerPosition;
    }

    size_t getNumberOfTables()
    {
        return cuckooTable.size();
    }

    uint64_t getEachTableSize()
    {
        return eachTableSize;
    }

    uint64_t getTableIndex(uint hfInd);
};
