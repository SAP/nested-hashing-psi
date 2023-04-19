/**
 * @file HierarchicalCuckooHashTable.cpp
 * 
 * @brief
 * @version 0.1
 *
 * Definition of the HierarchicalCuckooHashTable class.
 *
 */
#include "HierarchicalCuckooHashTable.hpp"
/**
 * @brief Class to manage a cuckoo hash table.
 *
 */

HierarchicalCuckooHashTable::HierarchicalCuckooHashTable(TabulationHashing &hashfunction,
                                                         uint64_t eachSimpleTableSize,
                                                         uint64_t eachCuckooTableSize,
                                                         uint64_t serverStashSize,
                                                         uint numberOfSimpleHashFunctions,
                                                         uint numberOfCuckooHashFunctions,
                                                         bool simpleMultiTables,
                                                         bool cuckooMultiTables,
                                                         uint64_t maxItemsPerPosition)
    : hashfunction(hashfunction),
      eachSimpleTableSize(eachSimpleTableSize),
      eachCuckooTableSize(eachCuckooTableSize),
      serverStashSize(serverStashSize),
      numberOfSimpleHashFunctions(numberOfSimpleHashFunctions),
      numberOfCuckooHashFunctions(numberOfCuckooHashFunctions),
      simpleMultiTables(simpleMultiTables),
      cuckooMultiTables(cuckooMultiTables),
      maxItemsPerPosition(maxItemsPerPosition)

{
  if (simpleMultiTables)
  {
    numberOfSimpleTables = numberOfSimpleHashFunctions;
  }
  else
  {
    numberOfSimpleTables = 1;
  }
  hierarchicalCuckooTable = vector<vector<CuckooHashTable>>(numberOfSimpleTables,
                                                            vector<CuckooHashTable>(eachSimpleTableSize,
                                                                                    CuckooHashTable(hashfunction,
                                                                                                    eachCuckooTableSize,
                                                                                                    numberOfCuckooHashFunctions,
                                                                                                    numberOfSimpleHashFunctions,
                                                                                                    serverStashSize,
                                                                                                    cuckooMultiTables,
                                                                                                    maxItemsPerPosition)));
}

void HierarchicalCuckooHashTable::insertAll(vector<biginteger> &elements)
{
  if (simpleMultiTables)
  {
    for (uint simpleTableIndex = 0; simpleTableIndex < numberOfSimpleHashFunctions; simpleTableIndex++)
    {

      vector<vector<biginteger>> simpleTable = generateSimpleHashTable(hashfunction, elements,
                                                                       simpleTableIndex, eachSimpleTableSize);

#pragma omp parallel for
      for (uint positionInSimple = 0; positionInSimple < simpleTable.size(); positionInSimple++)
      {

        // Could be parallized
        hierarchicalCuckooTable[simpleTableIndex][positionInSimple].insertAll(simpleTable[positionInSimple]);
      }
    }
  }
  else
  {

    vector<vector<biginteger>> multiTables = generateMultiHashSimpleHashTable(hashfunction, elements, 0,
                                                                              eachSimpleTableSize,
                                                                              numberOfSimpleHashFunctions);

#pragma omp parallel for
    for (uint positionInSimple = 0; positionInSimple < multiTables.size(); positionInSimple++)
    {
      hierarchicalCuckooTable[0][positionInSimple].insertAll(multiTables[positionInSimple]);
    }
  }
}