/**
 * @file FHEHIPPIE.cpp
 * 
 * @version 0.1
 *
 */
#include "FHEHIPPIE.hpp"

FHEHIPPIE::FHEHIPPIE(lbcrypto::CryptoContext<FHEEncType> &cryptor, lbcrypto::PublicKey<FHEEncType> &pK,
                     CuckooHashTable &ct) : cryptor(cryptor), pK(pK), numberOfResultElements(ct.getNumberOfHashFunctions())
{

    if (ct.getBinSize() != ct.getEachTableSize())
    {
        throw invalid_argument("Error, for FHE PIE the size of a cuckoo bin has to be equal than the number of bins per hash function.");
    }
    if (ct.stash.size() != 0)
    {
        throw invalid_argument("Error, FHE PIE does not support a stash (yet).");
    }
    initPermutationVector(numberOfResultElements);
    vectorizedCT = vector<vector<lbcrypto::Plaintext>>(ct.getNumberOfHashFunctions(),
                                                       vector<lbcrypto::Plaintext>(ct.getBinSize()));

    preCalcRandomMask = vector<lbcrypto::Plaintext>(ct.getNumberOfHashFunctions());

    // another Perm vector, hide correct bin index
    auto permVec2 = createPermutationVector(ct.getBinSize());

    auto plaintextModulus = cryptor->GetCryptoParameters()->GetPlaintextModulus();

    std::random_device rd;
    boost::random::mt19937 mt(rd());
    boost::random::uniform_int_distribution<int64_t> randGen;

    for (uint hfInd = 0; hfInd < ct.getNumberOfHashFunctions(); hfInd++)
    {

        auto preCalcRandomMaskTempVec = vector<int64_t>(ct.getBinSize());

        for (size_t binIndex = 0; binIndex < ct.getBinSize(); binIndex++)
        {
            // change from biginteger to uint for opennFHE
            // Add exponent for "minus client" element 1
            vector<int64_t> plainVec(ct.getEachTableSize() + 1);
            for (size_t hashPos = 0; hashPos < ct.getEachTableSize(); hashPos++)
            {
                plainVec[hashPos] = (int64_t)ct.cuckooTable[ct.getTableIndex(hfInd)][binIndex][hashPos];
            }
            plainVec[ct.getEachTableSize()] = 1;

            vectorizedCT[hfInd][permVec2[binIndex]] = cryptor->MakePackedPlaintext(plainVec);

            preCalcRandomMaskTempVec[binIndex] = randGen(mt) % (plaintextModulus - 1) + 1; // without 0
        }

        preCalcRandomMask[hfInd] = cryptor->MakePackedPlaintext(preCalcRandomMaskTempVec);
    }
}

void FHEHIPPIE::run()
{
    for (size_t hfInd = 0; hfInd < vectorizedCT.size(); hfInd++)
    {

        vector<lbcrypto::Ciphertext<FHEEncType>> binEvalsVec(vectorizedCT[hfInd].size());

        for (size_t binIndex = 0; binIndex < vectorizedCT[hfInd].size(); binIndex++)
        {

            binEvalsVec[binIndex] = cryptor->EvalInnerProduct(indexMatrix[hfInd], vectorizedCT[hfInd][binIndex], vectorizedCT[hfInd].size());
        }

        auto result = cryptor->EvalMult(cryptor->EvalMerge(binEvalsVec), preCalcRandomMask[hfInd]);
        shuffledResultList[permutationVector[hfInd]] = result;
    }
}