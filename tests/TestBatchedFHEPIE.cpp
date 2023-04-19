#include "openfhe.h"
#include <iostream>
#include "src/Common/Hashing/HierarchicalCuckooHashTable.hpp"
#include "src/Common/Crypto/PrivateIndexedEqualityCheck/BatchedFHEHIPPIE.hpp"

#ifndef defaultSerType
    #define defaultSerType lbcrypto::SerType::BINARY
#endif
int main(int argc, char *argv[])
{

    omp_set_num_threads(1); // Always use one thread for omp
    // Sample Program: Step 1 - Set CryptoContext
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters; 
    //PlaintextModulus n(65537);   
    PlaintextModulus n((1UL << 32) + (1UL << 20) + (1UL<< 19) + 1);   
    parameters.SetPlaintextModulus(n);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetBatchSize(2);

    //parameters.SetFirstModSize(60);
    //parameters.SetScalingModSize(60);
    
    parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
    

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    //cryptoContext->Enable(ADVANCEDSHE);


    // Initialize Public Key Containers
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    //Eval Sum Keys
    //cryptoContext->EvalSumKeyGen(keyPair.secretKey, keyPair.publicKey);

    //Eval Automorphism Key Gen
    // vector<int> rotateV(100);
    // for(size_t i = 0; i < rotateV.size(); i++) {

    //     rotateV[i] = -((int) i + 1);
    // }
    // cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotateV, keyPair.publicKey);

    uint64_t fixSeed = 122333444455555;
    boost::random::mt19937 mt(fixSeed);
    boost::random::uniform_int_distribution<uint64_t> randGen;

    int numberOfElem = 100;

    biginteger clientElem; 

    vector<biginteger> elemForCuckoo(numberOfElem);
    for (int i = 0; i < numberOfElem; i++)
    {
        biginteger randomUint = biginteger(0);
        while(randomUint == 0) {
            randomUint =  randomBiginteger(mt, randGen) % n;
        }
        elemForCuckoo[i] = randomUint;
    }

    bool clientElementEquals = true;
    cout << "Test should output matches twice" << endl;
    
    if(clientElementEquals) {
        clientElem = elemForCuckoo[numberOfElem / 2];
    } else {
        do{
            clientElem = randomBiginteger(mt, randGen) % n;
        }
        while((std::find(elemForCuckoo.begin(), elemForCuckoo.end(), clientElem) != elemForCuckoo.end()));
    }

    int64_t elem = (int64_t) clientElem;
    //(int64_t) randomModRange(n, mt, randGen);

    cout << "Element to compare: \t" << elem << endl;

    uint numberOfSimpleHashFunctions = 2;
    uint numberOfCuckooHashFunctions = 2;
    uint64_t eachSimpleTableSize = 1; 
    uint64_t cuckooHashTableSize = 10;
    uint64_t eachBinSize = 20;
    uint64_t stashSize = 0;

    TabulationHashing hashfu = TabulationHashing(12223222, numberOfSimpleHashFunctions + numberOfCuckooHashFunctions);
    HierarchicalCuckooHashTable hcT(hashfu, eachSimpleTableSize, cuckooHashTableSize, stashSize, 
                                    numberOfSimpleHashFunctions, numberOfCuckooHashFunctions, true, true, eachBinSize);
    hcT.insertAll(elemForCuckoo);

    vector<vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> indexMatrix(numberOfCuckooHashFunctions,
        vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(cuckooHashTableSize));

    for(uint hfInd = numberOfSimpleHashFunctions; hfInd < numberOfSimpleHashFunctions + numberOfCuckooHashFunctions; hfInd++) {
        
        uint_fast64_t hashIndex = calculateHashIndex(hashfu, clientElem, hfInd, cuckooHashTableSize);
        
        cout << "Hash index "<< hfInd << ": " << hashIndex << endl;
        for(uint64_t vectorIndex = 0; vectorIndex < cuckooHashTableSize; vectorIndex++) {
            vector<int64_t> plainIndexVec(2);

            if(vectorIndex == hashIndex) {
                plainIndexVec[0] = 1;
                plainIndexVec[1] = 1;

            } else {
                plainIndexVec[0] = 0;
                plainIndexVec[1] = 0;
            }
            auto packedVec = cryptoContext->MakePackedPlaintext(plainIndexVec);
            indexMatrix[hfInd - numberOfSimpleHashFunctions][vectorIndex] = cryptoContext->Encrypt(keyPair.secretKey, packedVec);
        }

    }

    BatchedFHEHIPPIE pie(cryptoContext, keyPair.publicKey, hcT);

    pie.setIndex(std::move(indexMatrix));


    //Compare element
    vector<int64_t> plainMinusEl(2);
    plainMinusEl[0] = -elem;
    plainMinusEl[1] = -elem;
    auto minusComp = cryptoContext->Encrypt(keyPair.secretKey, cryptoContext->MakePackedPlaintext(plainMinusEl));
    pie.setMinusCompareElement(minusComp);
    pie.run();

    for(auto encryptedResult : pie.getResultList()) {
        lbcrypto::Plaintext plaintext;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &plaintext);
        plaintext->SetLength(2);
        for(auto& plain : plaintext->GetPackedValue()) {
            //cout << plain << endl;
            if(plain == 0) {
                cout << "Matches" << endl;
            }
        }
    }
}
