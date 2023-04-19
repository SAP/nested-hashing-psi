#include "src/Common/Crypto/PrivateIndexedEqualityCheck/ElGamalPIE.hpp"
#include "src/Common/Crypto/PrivateIndexedEqualityCheck/PrecompElGamalPIE.hpp"
#include <iostream>

int main(int argc, char *argv[])
{


    std::random_device rd;
    boost::random::mt19937 mt(rd());
    boost::random::uniform_int_distribution<uint64_t> randGen;
    biginteger elem = randomBiginteger(mt, randGen);


    cout << "Element to compare: \t" << elem << endl;
    shared_ptr<DlogEllipticCurve> dlog = make_shared<OpenSSLDlogECFp>(OpenSSLCurveDir, "P-224"); 
    cout << "Generator: " << dlog->getGenerator()->generateSendableData()->toString() << endl; 
    AddHomElGamalEnc encryptor(dlog);

    
    auto pair = encryptor.generateKey();



    auto pk = ((ElGamalPublicKey*) (pair.first.get()))->generateSendableData()->toString();
    cout << "Public Key: " << pk << endl;
    encryptor.setKey(pair.first); //set public key only

 


    int numberOfElem = 20;

    biginteger clientElem; 

    vector<biginteger> elemForCuckoo(numberOfElem);
    for (int i = 0; i < numberOfElem; i++)
    {
        biginteger randomUint = biginteger(0);
        while(randomUint == 0) {
            randomUint =  randomBiginteger(mt, randGen);
        }
        elemForCuckoo[i] = randomUint;
    }

    bool clientElementEquals = true;
    cout << "Test should output: Matches" << pk << endl;

    if(clientElementEquals) {
        clientElem = elemForCuckoo[numberOfElem/ 2];
    } else {
        do{
            clientElem = randomBiginteger(mt, randGen);
        }
        while((std::find(elemForCuckoo.begin(), elemForCuckoo.end(), clientElem) != elemForCuckoo.end()));
    }


    uint numberOfCuckooHashFunctions = 3;
    uint64_t cuckooHashTableSize = 10;
    uint64_t stashSize = 5;


    TabulationHashing hashfu = TabulationHashing();
    CuckooHashTable cT(hashfu,cuckooHashTableSize,numberOfCuckooHashFunctions, 0, stashSize, true);
    cT.insertAll(elemForCuckoo);
    CuckooHashTable cT2(hashfu,cuckooHashTableSize,numberOfCuckooHashFunctions, 0, stashSize, true);
    cT2.insertAll(elemForCuckoo);


    vector<vector<shared_ptr<AsymmetricCiphertext>>> indexPtrMatrix(numberOfCuckooHashFunctions);
    vector<vector<AsymmetricCiphertext*>> indexMatrix(numberOfCuckooHashFunctions);
    shared_ptr<BigIntegerPlainText> plainOne = make_shared<BigIntegerPlainText>("1");
    shared_ptr<BigIntegerPlainText> plainZero = make_shared<BigIntegerPlainText>("0");

    for(uint hfInd = 0; hfInd < numberOfCuckooHashFunctions; hfInd++) {


        uint_fast64_t hashIndex = calculateHashIndex(hashfu, clientElem, hfInd, cuckooHashTableSize);
        #ifdef VERBOSE
        cout << "Hash index "<< hfInd << ": " << hashIndex << endl;
        #endif
        for(uint64_t vectorIndex = 0; vectorIndex < cuckooHashTableSize; vectorIndex++) {
            shared_ptr<BigIntegerPlainText> plain;
            if(vectorIndex == hashIndex) {
                plain = plainOne;

            } else {
                plain = plainZero;
            }
            shared_ptr<AsymmetricCiphertext> encryptedIndex = encryptor.encrypt(plain);
            indexPtrMatrix[hfInd].push_back(encryptedIndex);
            indexMatrix[hfInd].push_back(encryptedIndex.get());
        }
    }


    shared_ptr<BigIntegerPlainText> plaintextClient = make_shared<BigIntegerPlainText>(-clientElem);
    auto minusEncryptedClientElement = encryptor.encrypt(plaintextClient);


    #ifdef VERBOSE
        cout << "Test ElGamalPIE" << endl;
    #endif

    ElGamalPIE pie(encryptor, cT);

    pie.setIndexAndMinusCompareElement(std::move(indexMatrix), minusEncryptedClientElement.get());

    pie.run();

    encryptor.setKey(pair.first, pair.second); //now also set private key

    for(auto encryptedResult : pie.getResultList()) {
        auto decryptedPlaintext = encryptor.decrypt(encryptedResult.get());
        string plainDecrypted = decryptedPlaintext->generateSendableData()->toString();
        string identity = (dlog->getIdentity()->generateSendableData()->toString());
        #ifdef VERBOSE
        cout << plainDecrypted << endl;
        #endif
        if(plainDecrypted == identity) {
            cout << "Matches" << endl;
            break;
        };
    }


    #ifdef VERBOSE
        cout << "Test precomputed ElGamalPIE" << endl;
    #endif

    vector<vector<shared_ptr<AsymmetricCiphertext>>> precompIndexPtrMatrix(numberOfCuckooHashFunctions);
    vector<vector<AsymmetricCiphertext*>> precompIndexMatrix(numberOfCuckooHashFunctions);

    const size_t bitsetLength = numberOfCuckooHashFunctions * cuckooHashTableSize;
    auto mbitset = boost::dynamic_bitset<unsigned char>(bitsetLength);
    for(size_t i = 0; i < bitsetLength; i++){
        //Inefficient
        mbitset[i] = (bool) (randGen(mt) % 2);
    }
    cout << "Bitmask: " << mbitset << endl;
    size_t bitCounter = 0;
    for(uint hfInd = 0; hfInd < numberOfCuckooHashFunctions; hfInd++) {
        uint_fast64_t hashIndex = calculateHashIndex(hashfu, clientElem, hfInd, cuckooHashTableSize);
        #ifdef VERBOSE
        cout << "Hash index "<< hfInd << ": " << hashIndex << endl;
        #endif
        for(uint64_t vectorIndex = 0; vectorIndex < cuckooHashTableSize; vectorIndex++) {
            shared_ptr<BigIntegerPlainText> plain;
            if(mbitset[bitCounter]) {
                plain = plainOne;

            } else {
                plain = plainZero;
            }
            if(vectorIndex == hashIndex) {
                mbitset[bitCounter] = !mbitset[bitCounter];
            }
            shared_ptr<AsymmetricCiphertext> encryptedIndex = encryptor.encrypt(plain);
            precompIndexPtrMatrix[hfInd].push_back(encryptedIndex);
            precompIndexMatrix[hfInd].push_back(encryptedIndex.get());
            bitCounter++;
        }
    }



    PrecompElGamalPIE pie2(encryptor, cT2);

    pie2.setIndex(std::move(precompIndexMatrix));
    pie2.precomp();
    pie2.setMinusCompareElement(minusEncryptedClientElement.get());
    pie2.setBitVector(std::move(mbitset));
    pie2.run();

    for(auto& encryptedResult : pie2.getResultList()) {
        auto decryptedPlaintext = encryptor.decrypt(encryptedResult.get());
        string plainDecrypted = decryptedPlaintext->generateSendableData()->toString();
        string identity = (dlog->getIdentity()->generateSendableData()->toString());
        #ifdef VERBOSE
        cout << plainDecrypted << endl;
        #endif
        if(plainDecrypted == identity) {
            cout << "Matches" << endl;
            break;
        };
    }
}