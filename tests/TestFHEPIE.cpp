#include "openfhe.h"
#include <iostream>
#include "src/Common/Hashing/CuckooHashTable.hpp"
#include "src/Common/Crypto/PrivateIndexedEqualityCheck/FHEHIPPIE.hpp"

#ifndef defaultSerType
    #define defaultSerType lbcrypto::SerType::BINARY
#endif
int main(int argc, char *argv[])
{

    // Sample Program: Step 1 - Set CryptoContext
    lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters; 
    //PlaintextModulus n(65537);   
    PlaintextModulus n((1UL << 32) + (1UL << 20) + (1UL<< 19) + 1);   
    parameters.SetPlaintextModulus(n);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetBatchSize(100);

    //parameters.SetFirstModSize(60);
    //parameters.SetScalingModSize(60);
    
    parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
    

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    //cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);


    // Initialize Public Key Containers
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();


    //Eval Sum Keys
    cryptoContext->EvalSumKeyGen(keyPair.secretKey, keyPair.publicKey);

    //Eval Automorphism Key Gen
    vector<int> rotateV(100);
    for(size_t i = 0; i < rotateV.size(); i++) {

        rotateV[i] = -((int) i + 1);
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotateV, keyPair.publicKey);

    uint64_t fixSeed = 122333444455555;
    boost::random::mt19937 mt(fixSeed);
    boost::random::uniform_int_distribution<uint64_t> randGen;

    int numberOfElem = 15000;

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

    uint numberOfCuckooHashFunctions = 3;
    uint64_t cuckooHashTableSize = 100;
    uint64_t eachBinSize = 100;
    uint64_t stashSize = 0;

    TabulationHashing hashfu = TabulationHashing();
    CuckooHashTable cT(hashfu,cuckooHashTableSize,numberOfCuckooHashFunctions, 0, stashSize, true, eachBinSize);
    cT.insertAll(elemForCuckoo);

    vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> indexMatrix(numberOfCuckooHashFunctions);

    for(uint hfInd = 0; hfInd < numberOfCuckooHashFunctions; hfInd++) {
        vector<int64_t> plainIndexVec(cuckooHashTableSize + 1);
        uint_fast64_t hashIndex = calculateHashIndex(hashfu, clientElem, hfInd, cuckooHashTableSize);
        
        cout << "Hash index "<< hfInd << ": " << hashIndex << endl;
        for(uint64_t vectorIndex = 0; vectorIndex < cuckooHashTableSize; vectorIndex++) {
            shared_ptr<BigIntegerPlainText> plain;
            if(vectorIndex == hashIndex) {
                plainIndexVec[vectorIndex] = 1;

            } else {
                plainIndexVec[vectorIndex] = 0;
            }
        }
        plainIndexVec[cuckooHashTableSize] = -elem;

        auto packedVec = cryptoContext->MakePackedPlaintext(plainIndexVec);
        indexMatrix[hfInd] = cryptoContext->Encrypt(keyPair.secretKey, packedVec);
    }

    FHEHIPPIE pie(cryptoContext, keyPair.publicKey, cT);

    pie.setIndex(std::move(indexMatrix));

    pie.run();

    for(auto encryptedResult : pie.getResultList()) {
        lbcrypto::Plaintext plaintext;
        cryptoContext->Decrypt(keyPair.secretKey, encryptedResult, &plaintext);
        plaintext->SetLength(eachBinSize);
        for(auto& plain : plaintext->GetPackedValue()) {
            cout << plain << endl;
            if(plain == 0) {
                cout << "Matches" << endl;
                break;
            }
        }
    }
}
