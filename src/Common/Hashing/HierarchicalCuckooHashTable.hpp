/**
 * @file HierarchicalCuckooHashTable.hpp
 * 
 * @brief
 * @version 0.1
 *
 * Definition of the HierarchicalCuckooHashTable class.
 *
 */
#pragma once
#include "omp.h"
#include "CuckooHashTable.hpp"

/**
 * @brief Class to manage a cuckoo hash table.
 *
 */
class HierarchicalCuckooHashTable
{

private:
    TabulationHashing &hashfunction;
    const uint64_t eachSimpleTableSize;
    const uint64_t eachCuckooTableSize;
    const uint64_t serverStashSize;
    const uint numberOfSimpleHashFunctions;
    const uint numberOfCuckooHashFunctions;
    const bool simpleMultiTables;
    const bool cuckooMultiTables;
    const uint64_t maxItemsPerPosition;
    uint64_t numberOfSimpleTables;

public:
    vector<vector<CuckooHashTable>> hierarchicalCuckooTable;
    HierarchicalCuckooHashTable(TabulationHashing &hashfunction,
                                uint64_t eachSimpleTableSize,
                                uint64_t eachCuckooTableSize,
                                uint64_t serverStashSize = 0,
                                uint numberOfSimpleHashFunctions = 2,
                                uint numberOfCuckooHashFunctions = 2,
                                bool simpleMultiTable = false,
                                bool cuckooMultiTable = true,
                                uint64_t maxItemsPerPosition = 1);

    /**
     * @brief Iteratively place all elements into the cuckoo hash table
     * @param elements to insert
     */
    void insertAll(vector<biginteger> &elements);

    inline size_t getNumberOfSimpleTables()
    {
        return hierarchicalCuckooTable.size();
    }

    inline uint64_t getEachSimpleTableSize()
    {
        return eachSimpleTableSize;
    }

    inline size_t getNumberOfCuckooTables()
    {
        if (cuckooMultiTables)
        {
            return numberOfCuckooHashFunctions;
        }
        else
        {
            return 1;
        }
    }

    inline uint64_t getEachCuckooTableSize()
    {
        return eachCuckooTableSize;
    }

    inline uint64_t getServerStashSize()
    {
        return serverStashSize;
    }

    inline bool hasSimpleMultiTables()
    {
        return simpleMultiTables;
    }

    inline bool hasCuckooMultiTables()
    {
        return cuckooMultiTables;
    }

    inline uint64_t getEachBinSize()
    {
        return maxItemsPerPosition;
    }

    inline uint getNumberOfSimpleHashFunctions()
    {
        return numberOfSimpleHashFunctions;
    }
    inline uint getNumberOfCuckooHashFunctions()
    {
        return numberOfCuckooHashFunctions;
    }
};
