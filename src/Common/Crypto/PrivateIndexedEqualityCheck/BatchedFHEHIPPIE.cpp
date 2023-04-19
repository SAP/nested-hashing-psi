/**
 * @file BatchedFHEHIPPIE.cpp
 * 
 * @version 0.1
 *
 */
#include "BatchedFHEHIPPIE.hpp"

BatchedFHEHIPPIE::BatchedFHEHIPPIE(lbcrypto::CryptoContext<FHEEncType> &cryptoContext, lbcrypto::PublicKey<FHEEncType> &pK,
                                   HierarchicalCuckooHashTable &hct) : cryptoContext(cryptoContext), pK(pK)
{

    if (hct.getServerStashSize() != 0)
    {
        throw invalid_argument("Error, batched FHE PIE does not support a stash (yet).");
    }

    if (!hct.hasSimpleMultiTables() || !hct.hasCuckooMultiTables())
    {
        throw invalid_argument("Error, batched FHE PIE currently does not support combined tables.");
    }

    // Shuffle Bins beforehand

    std::random_device rd;
    boost::random::mt19937 mt(rd());

    for (auto &hctRow : hct.hierarchicalCuckooTable)
    {
        for (auto &ct : hctRow)
        {
            for (auto &ctRow : ct.cuckooTable)
                std::shuffle(std::begin(ctRow), std::end(ctRow), mt);
        }
    }

    vectorizedHCT = vector<vector<vector<lbcrypto::Plaintext>>>(hct.getNumberOfCuckooHashFunctions(),
                                                                vector<vector<lbcrypto::Plaintext>>(hct.getEachBinSize(),
                                                                                                    vector<lbcrypto::Plaintext>(hct.getEachCuckooTableSize())));

    size_t batchSize = hct.getNumberOfSimpleTables() * hct.getEachSimpleTableSize(); // assumes simple multi table!

    auto plaintextModulus = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();

    boost::random::uniform_int_distribution<int64_t> randGen;

    // change from biginteger to int64_t for openFHE
    for (uint innerHfInd = 0; innerHfInd < hct.getNumberOfCuckooTables(); innerHfInd++)
    {
        for (size_t binIndex = 0; binIndex < hct.getEachBinSize(); binIndex++)
        {
            for (size_t innerhashPos = 0; innerhashPos < hct.getEachCuckooTableSize(); innerhashPos++)
            {
                vector<int64_t> plainVec(batchSize);
                size_t batchIndex = 0;
                for (uint outerHfInd = 0; outerHfInd < hct.getNumberOfSimpleTables(); outerHfInd++)
                {

                    for (size_t outerhashPos = 0; outerhashPos < hct.getEachSimpleTableSize(); outerhashPos++)
                    {
                        auto &currentCT = hct.hierarchicalCuckooTable[outerHfInd][outerhashPos];
                        plainVec[batchIndex] = (int64_t)currentCT.cuckooTable[innerHfInd][binIndex][innerhashPos];
                        // important
                        batchIndex++;
                    }
                }

                vectorizedHCT[innerHfInd][binIndex][innerhashPos] = cryptoContext->MakePackedPlaintext(plainVec);
            }
        }
    }

    preCalcRandomMask = vector<lbcrypto::Plaintext>(hct.getEachBinSize());
    for (auto &randomMaskVec : preCalcRandomMask)
    {
        auto preCalcRandomMaskTempVec = vector<int64_t>(batchSize);
        for (auto &randomMask : preCalcRandomMaskTempVec)
        {
            randomMask = randGen(mt) % (plaintextModulus - 1) + 1; // without 0
        }
        randomMaskVec = cryptoContext->MakePackedPlaintext(preCalcRandomMaskTempVec);
    }

    // init result list
    resultList = vector<lbcrypto::Ciphertext<FHEEncType>>(hct.getEachBinSize());
}

void BatchedFHEHIPPIE::run()
{

    for (size_t binIndex = 0; binIndex < resultList.size(); binIndex++)
    {

        lbcrypto::Ciphertext<FHEEncType> multipliedResult;

        for (size_t innerHfInd = 0; innerHfInd < vectorizedHCT.size(); innerHfInd++)
        {

            lbcrypto::Ciphertext<FHEEncType> innerProductResult;

            for (size_t innerhashPos = 0; innerhashPos < vectorizedHCT[0][0].size(); innerhashPos++)
            {
                auto &currentEncryptedIndex = indexMatrix[innerHfInd][innerhashPos];
                auto &currentItem = vectorizedHCT[innerHfInd][binIndex][innerhashPos];

                if (innerhashPos == 0)
                {
                    innerProductResult = cryptoContext->EvalMult(currentEncryptedIndex, currentItem);
                }
                else
                {
                    innerProductResult = cryptoContext->EvalAdd(innerProductResult,
                                                                cryptoContext->EvalMult(currentEncryptedIndex, currentItem));
                }
            }
            innerProductResult = cryptoContext->EvalAdd(innerProductResult, minusCompareElement);
            if (innerHfInd == 0)
            {
                multipliedResult = innerProductResult;
            }
            else
            {
                multipliedResult = cryptoContext->EvalMult(multipliedResult, innerProductResult);
            }
        }
        multipliedResult = cryptoContext->EvalMult(multipliedResult, preCalcRandomMask[binIndex]);
        resultList[binIndex] = multipliedResult;
    }
}