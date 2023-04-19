/**
 * @file HIPPIE.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include "mid_layer/AsymmetricEnc.hpp"
#include "src/Common/Hashing/CuckooHashTable.hpp"

class HIPPIE
{
protected:
    CuckooHashTable &ct;
    vector<std::shared_ptr<AsymmetricCiphertext>> shuffledResultList;
    vector<uint> permutationVector;
    vector<vector<AsymmetricCiphertext *>> indexMatrix;
    AsymmetricCiphertext *minusCompareElement;
    uint numberOfResultElements;

    void initPermutationVector(uint numberOfResultElements)
    {
        permutationVector = createPermutationVector(numberOfResultElements);
        shuffledResultList = vector<std::shared_ptr<AsymmetricCiphertext>>(numberOfResultElements);
    }

public:
    HIPPIE(CuckooHashTable &ct, uint numberOfResultElements) : ct(ct), numberOfResultElements(numberOfResultElements)
    {
        initPermutationVector(numberOfResultElements);
    }

    virtual void run() = 0;

    vector<std::shared_ptr<AsymmetricCiphertext>> &getResultList()
    {
        return shuffledResultList;
    }

    void setIndexAndMinusCompareElement(vector<vector<AsymmetricCiphertext *>> &&indexMatrix, AsymmetricCiphertext *minusCompareElement)
    {
        setIndex(std::move(indexMatrix));
        setMinusCompareElement(minusCompareElement);
    }

    void setIndex(vector<vector<AsymmetricCiphertext *>> &&indexMatrix)
    {
        this->indexMatrix = indexMatrix;
    }

    void setMinusCompareElement(AsymmetricCiphertext *minusCompareElement)
    {
        this->minusCompareElement = minusCompareElement;
    }
};