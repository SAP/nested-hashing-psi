#pragma once
#include "infra/Common.hpp" //for correct uint64_t definitions, etc.
/**
 * @brief Struct to structure all nested cuckoo hashing parameters
 *
 */
struct HashTableParameter
{
    const uint64_t eachSimpleTableSize;
    const uint64_t eachCuckooTableSize;
    const uint64_t serverStashSize;
    const uint numberOfSimpleHashFunctions;
    const uint numberOfCuckooHashFunctions;
    const bool simpleMultiTable;
    const bool cuckooMultiTable;
    const uint64_t maxItemsPerPosition; // aka bin size (blocked Cuckoo Hashing)
    std::map<std::string, std::string> additionalParams;

    HashTableParameter(uint64_t eachSimpleTableSize,
                       uint64_t eachCuckooTableSize,
                       uint64_t serverStashSize,
                       uint numberOfSimpleHashFunctions,
                       uint numberOfCuckooHashFunctions,
                       bool simpleMultiTable,
                       bool cuckooMultiTable,
                       uint64_t maxItemsPerPosition) : eachSimpleTableSize(eachSimpleTableSize),
                                                       eachCuckooTableSize(eachCuckooTableSize),
                                                       serverStashSize(serverStashSize),
                                                       numberOfSimpleHashFunctions(numberOfSimpleHashFunctions),
                                                       numberOfCuckooHashFunctions(numberOfCuckooHashFunctions),
                                                       simpleMultiTable(simpleMultiTable),
                                                       cuckooMultiTable(cuckooMultiTable),
                                                       maxItemsPerPosition(maxItemsPerPosition)
    {
    }
};