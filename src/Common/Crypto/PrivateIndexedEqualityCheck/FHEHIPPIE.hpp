/**
 * @file FHEHIPPIE.hpp
 * 
 * @version 0.1
 *
 */
#include "openfhe.h"
#include "src/Common/Hashing/CuckooHashTable.hpp"

#ifndef FHEEncType
#define FHEEncType lbcrypto::DCRTPoly
#endif

#ifndef defaultSerType
#define defaultSerType lbcrypto::SerType::BINARY
#endif

class FHEHIPPIE
{
protected:
    lbcrypto::CryptoContext<FHEEncType> &cryptor;
    lbcrypto::PublicKey<FHEEncType> &pK;
    vector<vector<lbcrypto::Plaintext>> vectorizedCT;
    vector<lbcrypto::Ciphertext<FHEEncType>> shuffledResultList;
    vector<uint> permutationVector;
    vector<lbcrypto::Ciphertext<FHEEncType>> indexMatrix;
    vector<lbcrypto::Plaintext> preCalcRandomMask;
    uint numberOfResultElements;

    void initPermutationVector(uint numberOfResultElements)
    {
        permutationVector = createPermutationVector(numberOfResultElements);
        shuffledResultList = vector<lbcrypto::Ciphertext<FHEEncType>>(numberOfResultElements);
    }

public:
    FHEHIPPIE(lbcrypto::CryptoContext<FHEEncType> &cryptor, lbcrypto::PublicKey<FHEEncType> &pK,
              CuckooHashTable &ct);

    void run();

    vector<lbcrypto::Ciphertext<FHEEncType>> &getResultList()
    {
        return shuffledResultList;
    }

    void setIndex(vector<lbcrypto::Ciphertext<FHEEncType>> &&indexMatrix)
    {
        this->indexMatrix = indexMatrix;
    }
};