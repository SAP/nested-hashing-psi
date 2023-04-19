/**
 * @file BatchedFHEHIPPIE.hpp
 * 
 * @version 0.1
 *
 */
#include "openfhe.h"
#include "src/Common/Hashing/HierarchicalCuckooHashTable.hpp"

#ifndef FHEEncType
#define FHEEncType lbcrypto::DCRTPoly
#endif

#ifndef defaultSerType
#define defaultSerType lbcrypto::SerType::BINARY
#endif

class BatchedFHEHIPPIE
{
protected:
    lbcrypto::CryptoContext<FHEEncType> &cryptoContext;
    lbcrypto::PublicKey<FHEEncType> &pK;
    vector<vector<vector<lbcrypto::Plaintext>>> vectorizedHCT; // chfN x bin x chfIndex
    vector<lbcrypto::Ciphertext<FHEEncType>> resultList;
    vector<vector<lbcrypto::Ciphertext<FHEEncType>>> indexMatrix; // chfN x chfIndex
    lbcrypto::Ciphertext<FHEEncType> minusCompareElement;
    vector<lbcrypto::Plaintext> preCalcRandomMask;

public:
    BatchedFHEHIPPIE(lbcrypto::CryptoContext<FHEEncType> &cryptor, lbcrypto::PublicKey<FHEEncType> &pK,
                     HierarchicalCuckooHashTable &hct);

    void run();

    vector<lbcrypto::Ciphertext<FHEEncType>> &getResultList()
    {
        return resultList;
    }

    void setIndex(vector<vector<lbcrypto::Ciphertext<FHEEncType>>> &&indexMatrix)
    {
        this->indexMatrix = indexMatrix;
    }

    void setMinusCompareElement(lbcrypto::Ciphertext<FHEEncType> minusCompareElement)
    {
        this->minusCompareElement = minusCompareElement;
    }
};