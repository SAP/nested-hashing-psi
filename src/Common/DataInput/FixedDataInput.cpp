/**
 * @file FixedDataInput.cpp
 * 
 * @version 0.1
 */

#include "FixedDataInput.hpp"
#include "../Hashing/HashUtils.hpp"
#include <math.h> 

FixedDataInput::FixedDataInput(size_t serverSetSize,
                               size_t clientSetSize,
                               size_t intersectionSetSize,
                               uint64_t bitSize)
    : bitSize(bitSize)
{

    assert(clientSetSize <= serverSetSize);
    assert(intersectionSetSize <= clientSetSize);
    assert(bitSize > log2(clientSetSize + serverSetSize - intersectionSetSize));

    serverSet = vector<biginteger>(serverSetSize);
    clientSet = vector<biginteger>(clientSetSize);
    intersectionSet = vector<biginteger>(intersectionSetSize);
    uint numberOfDummyValues = 2;

    std::iota(clientSet.begin(), clientSet.end(), numberOfDummyValues);
    std::iota(intersectionSet.begin(), intersectionSet.end(), clientSetSize + numberOfDummyValues - intersectionSetSize);
    std::iota(serverSet.begin(), serverSet.end(), clientSetSize + numberOfDummyValues - intersectionSetSize);
}

std::vector<biginteger> &FixedDataInput::getClientSet()
{
    return clientSet;
}

std::vector<biginteger> &FixedDataInput::getServerSet()
{
    return serverSet;
}

std::vector<biginteger> &FixedDataInput::getIntersectionSet()
{
    return intersectionSet;
}
