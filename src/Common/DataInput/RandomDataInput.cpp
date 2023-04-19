/**
 * @file RandomDataInput.cpp
 * 
 * @version 0.1
 */

#include "RandomDataInput.hpp"
#include "../Hashing/HashUtils.hpp"

RandomDataInput::RandomDataInput(size_t serverSetSize,
                        size_t clientSetSize,
                        size_t intersectionSetSize, 
                        uint64_t setGenerationSeed, 
                        uint64_t bitSize)
                        :
                        bitSize(bitSize),
                        mtClient(boost::random::mt19937(setGenerationSeed)),
                        mtServer(boost::random::mt19937(setGenerationSeed + serverSeedDiff)),
                        randGen(boost::random::uniform_int_distribution<uint64_t>()){

   
    assert(clientSetSize <= serverSetSize);
    assert(intersectionSetSize <= clientSetSize);
    assert(bitSize > log2(clientSetSize + serverSetSize - intersectionSetSize));

    serverSet = vector<biginteger>(serverSetSize);
    clientSet = vector<biginteger>(clientSetSize);
    intersectionSet = vector<biginteger>(intersectionSetSize);
}

void RandomDataInput::generateClientAndIntersectionSet() {

 
    size_t onlyClientSize = clientSet.size()- intersectionSet.size();
    for(uint i = 0; i < clientSet.size(); i++) {
        
        if(i < onlyClientSize) {
            biginteger currentElement = randomBiginteger(mtClient, randGen, bitSize);
            clientSet[i] = currentElement;
        } else {
            biginteger currentElement = randomBiginteger(mtServer, randGen, bitSize);
            clientSet[i] = currentElement;
            intersectionSet[i - onlyClientSize] = currentElement;
            serverSet[i - onlyClientSize] = currentElement;
        }
    }
    clientAndIntersectionSetGenerated = true;
}

void RandomDataInput::generateServerSet() {

    size_t startIndex = 0;

    if(clientAndIntersectionSetGenerated) {

        startIndex = clientSet.size() - intersectionSet.size();
    } 
 
    for(; startIndex < serverSet.size(); startIndex++) {
        
        biginteger currentElement = randomBiginteger(mtServer, randGen, bitSize);

        serverSet[startIndex] = currentElement;
    }
            
    serverSetGenerated = true;
}


bool RandomDataInput::isNotAllowed(biginteger& testValue) {
    //TODO: Include/Refactor
    return (testValue == 0) or (testValue == 1);
}

std::vector<biginteger>& RandomDataInput::getClientSet() {
    if(clientAndIntersectionSetGenerated) {
        return clientSet;
    } else if (serverSetGenerated) {
        __throw_logic_error("Try to generate client set after server set, prohibited");
    } else {
        generateClientAndIntersectionSet();
        return clientSet;
    }
}

std::vector<biginteger>& RandomDataInput::getServerSet() {
    if(! serverSetGenerated) {
        generateServerSet();
    } 
    return serverSet;
}

std::vector<biginteger>& RandomDataInput::getIntersectionSet() {
    if(clientAndIntersectionSetGenerated) {
        return intersectionSet;
    } else if (serverSetGenerated) {
        __throw_logic_error("Try to generate intersection set after server set, not supported");
    } else {
        generateClientAndIntersectionSet();
        return intersectionSet;
    }
}
