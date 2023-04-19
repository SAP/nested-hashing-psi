/**
 * @file CuckooHashTable.cpp
 * 
 * @brief
 * @version 0.1
 *
 * Implementation of the CuckooHashTable class.
 *
 */

#include "CuckooHashTable.hpp"

/**
 * @brief Construct a new Cuckoo Hasher:: Cuckoo Hasher object
 *
 * @param hashfunction The hash function that will be used
 * @note Is used for all hash positions by adding different identifier to the hash input
 *
 * @param eachTableSize Size of each single hash table
 * @param numberOfHashFunctions Number of different hash function slots
 * @param numberOfRetries Max loop counter for insertion failures
 * @param multipleTables Cuckoo hashing variant selection
 *
 */
CuckooHashTable::CuckooHashTable(TabulationHashing &hashfunction,
                                 uint64_t eachTableSize,
                                 uint numberOfHashFunctions,
                                 uint startingHashId,
                                 uint64_t maxStashSize,
                                 bool multipleTables,
                                 uint64_t maxItemsPerPosition)
    : hashfunction(hashfunction),
      eachTableSize(eachTableSize),
      startingHashId(startingHashId),
      maxStashSize(maxStashSize),
      multipleTables(multipleTables),
      maxItemsPerPosition(maxItemsPerPosition)
{
    if (numberOfHashFunctions < 2)
    {
        throw invalid_argument("Cuckoo Table needs more than one hash function!");
    }
    if (maxItemsPerPosition < 1)
    {

        throw invalid_argument("Bin size needs to be at least of size one!");
    }
    this->numberOfHashFunctions = numberOfHashFunctions;
    // A bit ugly, hopefully fast (Take care: maxItemsPerPosition defines the second axes, not the third)

    std::random_device rd;
    mt = boost::random::mt19937(rd());
    boost::random::uniform_int_distribution<uint64_t> randGen;

    if (multipleTables)
    {
        cuckooTable = vector<vector<vector<biginteger>>>(numberOfHashFunctions, vector<vector<biginteger>>(maxItemsPerPosition, vector<biginteger>(eachTableSize)));
    }
    else
    {
        cuckooTable = vector<vector<vector<biginteger>>>(1, vector<vector<biginteger>>(maxItemsPerPosition, vector<biginteger>(eachTableSize)));
    }

    stash = vector<biginteger>(maxStashSize);
}

/**
 * @brief Function to insert a value into the cuckoo hash table
 *
 * @param value that should be inserted into the table
 */
void CuckooHashTable::insert(biginteger &value)
{
    if (lookUp(value))
    {
        return;
    }
    for (uint run = 0; run < numberOfRetries; run++)
    {
        for (uint hfInd = 0; hfInd < numberOfHashFunctions; hfInd++)
        {

            uint_fast64_t hashIndex = calculateHashIndex(hashfunction, value, startingHashId + hfInd, eachTableSize);

            uint64_t tableIndex = getTableIndex(hfInd);

            for (uint binIndex = 0; binIndex < cuckooTable[tableIndex].size(); binIndex++)
            {
                // Zero assumed to be dummy, needs to be evaluated
                if (cuckooTable[tableIndex][binIndex][hashIndex] == 0)
                {
                    cuckooTable[tableIndex][binIndex][hashIndex] = value;
                    return;
                }
            }

            // Choose random bin element
            uint reinsertIndex = randomModRange(cuckooTable[tableIndex].size(), mt, randGen);

            // Swap
            boost::swap(value, cuckooTable[tableIndex][reinsertIndex][hashIndex]);
        }
    }
    for (uint i = 0; i < stash.size(); i++)
    {
        // 0 is dummy element
        if (stash[i] == 0)
        {
            stash[i] = value;
            return;
        }
    }
    throw runtime_error("(Blocked) Cuckoo hashing error");
}

/**
 * @brief Iteratively place all elements into the cuckoo hash table
 *
 */
void CuckooHashTable::insertAll(vector<biginteger> &elements)
{
    for (auto currentElement : elements)
    {
        insert(currentElement);
    }
}

/**
 * @brief Checks whether cuckoo table has element
 *
 * @param element
 * @return true
 * @return false element not in Cuckoo table
 */
bool CuckooHashTable::lookUp(biginteger &element)
{
    // if(element == 0) {
    //     throw invalid_argument("Should never need to lookUp dummy element 0.");
    // }
    for (uint hfInd = 0; hfInd < numberOfHashFunctions; hfInd++)
    {
        uint_fast64_t hashIndex = calculateHashIndex(hashfunction, element,
                                                     startingHashId + hfInd, eachTableSize);

        for (uint binIndex = 0; binIndex < cuckooTable[getTableIndex(hfInd)].size(); binIndex++)
        {

            biginteger &currElem = cuckooTable[getTableIndex(hfInd)][binIndex][hashIndex];
            if (currElem == element)
            {
                return true;
            }
            else if (currElem == 0)
            {
                break;
            }
        }
    }
    for (auto stashElem : stash)
    {
        if (stashElem == element)
        {
            return true;
        }
    }
    return false;
}

uint64_t CuckooHashTable::getTableIndex(uint hfInd)
{

    if (multipleTables)
    {
        return hfInd;
    }
    else
    {
        return 0;
    }
}