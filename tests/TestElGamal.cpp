#include <iostream>
#include <vector>
#include <string>
#include "mid_layer/DamgardJurikEnc.hpp"
#include "src/Common/Crypto/AddHomElGamalEnc.hpp"
#include "src/Common/Hashing/CuckooHashTable.hpp"
#include "src/Common/Hashing/HierarchicalCuckooHashTable.hpp"
#include "src/Common/Hashing/HashUtils.hpp"
#include "primitives/DlogOpenSSL.hpp"
#include "primitives/HashOpenSSL.hpp"



int main(int argc, char *argv[])
{
    cout << "Generate plaintexts";
    uint64_t seed = 5423645346;
    boost::random::mt19937 mt(seed);
    boost::random::uniform_int_distribution<uint64_t> randInt64;
    for (int i = 0; i < 10; i++)
    {
        biginteger random = randInt64(mt);
        random = (random << 64) ^ randInt64(mt);
        cout << random << endl;
    }

    cout << "Test AddHom Elg" << endl;
    shared_ptr<DlogGroup> dlog = make_shared<OpenSSLDlogECF2m>(OpenSSLCurveDir, "K-283");
    cout << "dlog generated" << endl;

    // Create an ElGamalOnGroupElement encryption object.
    AddHomElGamalEnc elGamal(dlog);

    // Generate a keyPair using the ElGamal object.
    auto pair = elGamal.generateKey();

    // Set private key and party2's public key:
    elGamal.setKey(pair.first, pair.second);
    cout << "Key set" << endl;
    // Create a biginteger to encrypt and encrypt the plaintext.
    shared_ptr<BigIntegerPlainText> plaintext = make_shared<BigIntegerPlainText>("100");
    shared_ptr<AsymmetricCiphertext> cipher1 = elGamal.encrypt(plaintext);
    shared_ptr<BigIntegerPlainText> plaintext2 = make_shared<BigIntegerPlainText>("400");
    shared_ptr<AsymmetricCiphertext> cipher2 = elGamal.encrypt(plaintext2);
    cout << "Encrypted" << endl;

    biginteger oneHundred = biginteger(-2);
    cipher1 = elGamal.multByConst(cipher1.get(), oneHundred);

    cout << "Multiplied" << endl;
    auto cipherOut = elGamal.add(cipher1.get(), cipher2.get());
    cipherOut = elGamal.add(cipherOut.get(), cipher1.get());

    cout << "Added" << endl;
    // Get the ciphertext and decrypt it to get the plaintext.
    shared_ptr<Plaintext> plaintextOut = elGamal.decrypt(cipherOut.get());
    cout << "Decrypted" << endl;
    // Get the plaintext element and use it as needed.
    GroupElement *element = ((GroupElementPlaintext *)plaintextOut.get())->getElement().get();
    cout << "Check if equal" << endl;
    cout << element->generateSendableData()->toString() << endl;

    biginteger oneHundredTwenty = biginteger(0);
    std::shared_ptr<GroupElement> compValue = dlog->exponentiate(dlog->getGenerator().get(), oneHundredTwenty);
    cout << compValue->generateSendableData()->toString() << endl;
    cout << "Done" << endl;

    cout << "Test ElGamal plaintext XOR" << endl;
    shared_ptr<BigIntegerPlainText> plaintextZero = make_shared<BigIntegerPlainText>("0");
    shared_ptr<BigIntegerPlainText> plaintextOne = make_shared<BigIntegerPlainText>("1");

    shared_ptr<AsymmetricCiphertext> cipherZero = elGamal.encrypt(plaintextZero);
    shared_ptr<AsymmetricCiphertext> cipherOne = elGamal.encrypt(plaintextOne);

    auto cipher0XOR0 = elGamal.xorByConst(cipherZero.get(), false);
    auto cipher0XOR1 = elGamal.xorByConst(cipherZero.get(), true);
    auto cipher1XOR0 = elGamal.xorByConst(cipherOne.get(), false);
    auto cipher1XOR1 = elGamal.xorByConst(cipherOne.get(), true);

    shared_ptr<Plaintext> plaintext0XOR0 = elGamal.decrypt(cipher0XOR0.get());
    shared_ptr<Plaintext> plaintext0XOR1 = elGamal.decrypt(cipher0XOR1.get());
    shared_ptr<Plaintext> plaintext1XOR0 = elGamal.decrypt(cipher1XOR0.get());
    shared_ptr<Plaintext> plaintext1XOR1 = elGamal.decrypt(cipher1XOR1.get());

    cout << "0 XOR 0: " << plaintext0XOR0->generateSendableData()->toString() << endl;
    cout << "0 XOR 1: " << plaintext0XOR1->generateSendableData()->toString() << endl;
    cout << "1 XOR 0: " << plaintext1XOR0->generateSendableData()->toString() << endl;
    cout << "1 XOR 1: " << plaintext1XOR1->generateSendableData()->toString() << endl;
    cout << "Generator:" << dlog->getGenerator()->generateSendableData()->toString() << endl;

    cout << "Test ElGamal ciphertext reconstruction" << endl;
    shared_ptr<BigIntegerPlainText> plaintextSend = make_shared<BigIntegerPlainText>("0");
    shared_ptr<AsymmetricCiphertext> cipherSend = elGamal.encrypt(plaintextSend);
    string s(cipherSend->generateSendableData()->toString());
#ifdef VERBOSE
    cout << s << endl
         << "Reconstruct:" << endl;
#endif

    shared_ptr<AsymmetricCiphertext> cipherRecv = elGamal.reconstructCiphertext(s);
    string s2(cipherRecv->generateSendableData()->toString());
#ifdef VERBOSE
    cout << s2 << endl;
#endif

#ifdef VERBOSE
    cout << "Match: " << to_string((s == s2)) << endl;
#endif
    shared_ptr<Plaintext> plaintextRecv = elGamal.decrypt(cipherRecv.get());

    cout << "Decrypted: " << plaintextRecv->generateSendableData()->toString();

    cout << "Test (Hierarchical) Cuckoo Hashing" << endl;

    TabulationHashing hashfu = TabulationHashing(12431412512, 5);
    std::random_device dev;
    boost::random::mt19937 mt2(dev());

    int numberOfElementsForHC = 20;
    int numberOfClientElem = 2;

    vector<biginteger> elemForHC(numberOfElementsForHC);
    vector<biginteger> elemForC(numberOfClientElem);
    for (int i = 0; i < numberOfElementsForHC; i++)
    {
        biginteger randomUint = biginteger(0);
        while(randomUint == 0) {
            randomUint =  randomBiginteger(mt2, randInt64);
        }
        if (i < 50 && i < numberOfClientElem)
        {
            elemForC[i] = randomUint;
        }
        elemForHC[i] = randomUint;
        cout << elemForHC[i] << endl;
        // cout << (uint64_t) elemForHC[i] << endl;
        // cout << (uint64_t) (elemForHC[i] >> 64) << endl;
        // cout << hashfu.hashWithIndicator(randomUint, 0) << endl;
        // cout << hashfu.hashWithIndicator(randomUint, 1) << endl;
        // cout << hashfu.hashWithIndicator(randomUint, 2) << endl;
        // cout << hashfu.hashWithIndicator(randomUint, 3) << endl;
        
        // for(int j = 0; j < 16; j++) {
        //     cout << (uint) ((unsigned char) (randomUint)) << endl;
        //     randomUint = randomUint >> 8;
        // }

    }

    uint numberOfSimpleHashFunctions = 2;
    uint numberOfCuckooHashFunctions = 2;
    uint64_t simpleHashTableSize = 8;
    uint64_t CuckooHashTableSize = 10;

    HierarchicalCuckooHashTable hcT(hashfu, simpleHashTableSize, CuckooHashTableSize, 0,
                                    numberOfSimpleHashFunctions, numberOfCuckooHashFunctions, true, true);
    hcT.insertAll(elemForHC);
    
    for(auto row: hcT.hierarchicalCuckooTable) {
        for(auto ctR: row) {
            for(auto cRow: ctR.cuckooTable) {
                for(auto value: cRow[0]) {
                    if(value != 0)
                    cout << value << endl;
                }
                cout << "&&&&" << endl;
            }
            cout << "&&&&&&&&" << endl;
        }
        cout << "& & & & & & &" << endl;
    }
    
   CuckooHashTable cT(hashfu,simpleHashTableSize,2);
   cT.insertAll(elemForC);
    /*
     cout << "Test index hashing" << endl;
     auto tV = randInt64(mt2);
     cout << tV << endl;
     for(int i = 0; i < 10; i++){
         cout << calculateHash(hashfu, tV,i) << endl;
         cout << "&&&&&&" << endl;
     }
     */
    cout << "Test cuckoo hashing plus hcuckoo hashing" << endl;
    uint clientItemsInserted = 0;
    uint foundItems = 0;
    for(size_t i = 0; i < cT.cuckooTable.size(); i++) {
        for(size_t j = 0; j < cT.cuckooTable[i][0].size(); j++) {
            biginteger curEl = cT.cuckooTable[i][0][j];
            if(curEl == 0) {
                continue;
            }
            clientItemsInserted ++;
            bool found = hcT.hierarchicalCuckooTable[i][j].lookUp(curEl);
            if(found) {
                foundItems ++;
            }
        }
    }
    cout << "Found " << foundItems << " of " << numberOfClientElem << endl;
    cout << "Client Items in table: " << clientItemsInserted << endl; 


    // cout << "Simple One Multi Table" << endl;

    // HierarchicalCuckooHashTable hcT2(hashfu, simpleHashTableSize, CuckooHashTableSize,
    //                                 2, numberOfSimpleHashFunctions, numberOfCuckooHashFunctions);
    // hcT2.insertAll(elemForHC);
    
    // for(auto row: hcT2.hierarchicalCuckooTable) {
    //     for(auto ctR: row) {
    //         for(auto cRow: ctR.cuckooTable) {
    //             for(auto value: cRow[0]) {
    //                 cout << value << endl;
    //             }
    //             cout << "&&&&" << endl;
    //         }
    //         cout << "&&&&&&&&" << endl;
    //         cout << "Stash:" << endl;
    //          for(auto val: ctR.stash) {
    //              cout << val << endl;
    //          } 
    //     }
    //     cout << "& & & & & & &" << endl;
    // }
}