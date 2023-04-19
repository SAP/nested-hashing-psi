#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include "mid_layer/DamgardJurikEnc.hpp"
#include "comm/Comm.hpp"
using namespace std;
using namespace boost::multiprecision;
using namespace boost::random;


int main(int argc, char* argv[]) {

    string ip = "127.0.0.1";
    int port = 8000;
    //int numParties = 2;
    bool verbose = false;
    
    int array_size = atoi(argv[1]);
    int key_length = atoi(argv[2]);
    string fileName = "M_S" + to_string(array_size) + "_K" + to_string(key_length) + ".csv";
    ofstream MyFile(fileName);
    SocketPartyData me, other;
    boost::asio::io_service io_service;

    me = SocketPartyData(boost_ip::address::from_string(ip), port + 1);
    cout<<"my port = "<<port << endl;
    other = SocketPartyData(boost_ip::address::from_string(ip), port);
    cout<<"other port = "<<port + 1 <<endl;

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
    // connect to party one
    channel->join(500, 5000);
    cout<<"channel established"<<endl;
    
    cout<<"Generate plaintexts"<<endl;
    uint64_t seed = 1498165861356;
    boost::random::mt19937 mt(seed);     
    boost::random::uniform_int_distribution<uint64_t> randInt64;

    vector<uint64_t> serverSet;
    cout << "Element at index:" << endl;
    for(int index = 0; index < array_size; index ++) {
        uint64_t generatedElem = randInt64(mt);
        if(verbose) {
            cout << index << "\t \t" << generatedElem << endl;
        }
        serverSet.push_back(generatedElem);
    }

    cout << "Receive public key:"<<endl;
    
    vector<unsigned char> pkVector;
    channel->readWithSizeIntoVector(pkVector);
    
    DamgardJurikPublicKey pk(1); //Initialize with fake modulus, might fix
    pk.initFromByteVector(pkVector);

    DamgardJurikEnc encryptor;
    auto pkP = encryptor.reconstructPublicKey(&pk);
    encryptor.setKey(pkP);
    encryptor.setLengthParameter(1);
    

    cout << "Read index Vector" << endl;
    biginteger modulus = ((DamgardJurikPublicKey *) encryptor.getPublicKey().get())->getModulus();
    biginteger minusOne = modulus - 1;
    vector<AsymmetricCiphertext*> indexVector;
    auto ready = chrono::high_resolution_clock::now();
    for(int index = 0; index < array_size; index++) {
        vector<unsigned char> *cipherVector = new vector<unsigned char>(75);
        channel->readWithSizeIntoVector(*cipherVector);
        BigIntegerCiphertext* bICiphertext = new BigIntegerCiphertext(1);
        bICiphertext->initFromByteVector(*cipherVector);
        indexVector.push_back(bICiphertext);
    }
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - ready);
     MyFile << "Send Index Vector," << duration.count() << endl;

    
    if(verbose) {
        for(size_t i = 0 ; i < indexVector.size(); i ++) {
            cout << indexVector.at(i)->generateSendableData().get()->toString() << endl;
        }
    }

    cout << "Multiplication" << endl;
    auto start = chrono::high_resolution_clock::now();
    vector<shared_ptr<AsymmetricCiphertext>> multipliedVector;
    for(size_t index = 0; index < indexVector.size(); index ++){
        biginteger elemAtIndex = (biginteger) serverSet.at(index);
        multipliedVector.push_back(encryptor.multByConst(indexVector.at(index), elemAtIndex));
    }
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    MyFile << "Multiplication," << duration.count() << endl;

    if(verbose) {
        for(size_t i = 0 ; i < indexVector.size(); i ++) {
            cout << multipliedVector.at(i)->generateSendableData().get()->toString() << endl;
        }
    }
    cout << "Addition" << endl;
    auto addUpCiphertext = multipliedVector.at(0); // assume at least one element in the list
    start = chrono::high_resolution_clock::now();
    for(size_t index = 1; index < multipliedVector.size(); index ++) {

        addUpCiphertext = encryptor.add(addUpCiphertext.get(), multipliedVector.at(index).get());
    }
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    MyFile << "Addition," << duration.count() << endl;

    


    cout << "Receive cipher to compare"<<endl;
    start = chrono::high_resolution_clock::now();
    vector<unsigned char> cipherVector;
    channel->readWithSizeIntoVector(cipherVector);
    BigIntegerCiphertext* bICiphertext = new BigIntegerCiphertext(1);
    bICiphertext->initFromByteVector(cipherVector);
    auto cipherText = encryptor.reconstructCiphertext(bICiphertext);

    cout << "Subtract and Obfuscate" << endl;
    addUpCiphertext = encryptor.multByConst(addUpCiphertext.get(), minusOne);
    cipherText = encryptor.add(cipherText.get(), addUpCiphertext.get());

    biginteger obfuscator = (biginteger) randInt64(mt); //TODO Should avoid 0 (which is negligeable)
    cipherText = encryptor.multByConst(cipherText.get(), obfuscator);

    string cipherTextString = ((BigIntegerCiphertext*) cipherText.get())->toString();


    cout << "Encrypted value" << cipherTextString << endl;

    channel->writeWithSize(cipherTextString);

    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    MyFile << "Rec-Sub-Obf," << duration.count() << endl;
    duration = chrono::duration_cast<chrono::microseconds>(stop - ready);
    MyFile << "Overall," << duration.count() << endl;
}


    