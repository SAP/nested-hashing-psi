#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include "src/Common/Crypto/AddHomElGamalEnc.hpp"
#include "src/PSIConfigs.h"
#include "comm/Comm.hpp"
using namespace std;
using namespace boost::multiprecision;
using namespace boost::random;




int main(int argc, char* argv[]) {

    string ip = "127.0.0.1";
    int port = 8000;
    //int numParties = 2;
    const bool verbose = false;

    const int array_size = atoi(argv[1]);

    
    string curve_name(argv[2]);

    
    shared_ptr<DlogEllipticCurve> dlog = make_shared<OpenSSLDlogECF2m>(OpenSSLCurveDir, curve_name);  
    cout << "Is prime group: " << dlog.get()->isPrimeOrder() << endl;
    cout << "Generator: " << dlog->getGenerator()->generateSendableData()->toString() << endl;

    string fileName = "ECCSIMP_M_S" + to_string(array_size) + "C" + dlog->getCurveName() + ".csv";
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

    vector<biginteger> serverSet;
    cout << "Element at index:" << endl;
    for(int index = 0; index < array_size; index ++) {
        uint64_t generatedElem = randInt64(mt);
        serverSet.push_back(biginteger(generatedElem));
        if(verbose) {
            cout << index << "\t \t" << generatedElem << endl;
        }
    }

    cout << "Receive public key:"<<endl;
    
    vector<unsigned char> pkVector;
    channel->readWithSizeIntoVector(pkVector);
       
    shared_ptr<GroupElementSendableData> dummy = dlog.get()->getGenerator().get()->generateSendableData();
    ElGamalPublicKeySendableData pkS(dummy);
    pkS.initFromByteVector(pkVector);
    AddHomElGamalEnc encryptor(dlog);
    auto pkP = encryptor.reconstructPublicKey(&pkS);
    encryptor.setKey(pkP);
    cout << "Public Key: " <<  pkS.toString() << endl;

    
    biginteger minusOne = biginteger(-1);
    cout << "Read index Vector" << endl;
    vector<shared_ptr<AsymmetricCiphertext>> indexVector;
    vector<shared_ptr<GroupElement>> uVector;
    vector<shared_ptr<GroupElement>> vVector;
    auto ready = chrono::high_resolution_clock::now();
    for(int index = 0; index < array_size; index++) {
        vector<unsigned char> cipherVector;
        channel->readWithSizeIntoVector(cipherVector);
        auto cipherTextSend = encryptor.reconstructCiphertext(cipherVector, true);
        indexVector.push_back(cipherTextSend);
        uVector.push_back(((ElGamalOnGroupElementCiphertext *) cipherTextSend.get())->getC1());
        vVector.push_back(((ElGamalOnGroupElementCiphertext *) cipherTextSend.get())->getC2());
    }
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - ready);
    MyFile << "Send Index Vector," << duration.count() << endl;

    auto c1 = dlog->simultaneousMultipleExponentiations(uVector, serverSet);
    auto c2 = dlog->simultaneousMultipleExponentiations(vVector, serverSet);

    shared_ptr<AsymmetricCiphertext> addUpCiphertext = make_shared<ElGamalOnGroupElementCiphertext>(c1, c2);



    auto start = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(start - stop);
    MyFile << "MultiAdd, " << duration.count() << endl;
    cout << "Receive cipher to compare"<<endl;
    vector<unsigned char> cipherVector;
    channel->readWithSizeIntoVector(cipherVector);
    shared_ptr<AsymmetricCiphertext> cipherText = encryptor.reconstructCiphertext(cipherVector);


    cout << "Subtract and Obfuscate" << endl;
    addUpCiphertext = encryptor.multByConst(addUpCiphertext.get(),minusOne);
    cipherText = encryptor.add(cipherText.get(), addUpCiphertext.get());

    biginteger obfuscator = (biginteger) randInt64(mt); //TODO Should avoid 0 (which is negligeable)
    cipherText = encryptor.multByConst(cipherText.get(), obfuscator);

    string cipherTextString = ((ElGamalOnGroupElementCiphertext*) cipherText.get())->generateSendableData()->toString();


    cout << "Encrypted value" << cipherTextString << endl;

    channel->writeWithSize(cipherTextString);

    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    MyFile << "Rec-Sub-Obf," << duration.count() << endl;
    duration = chrono::duration_cast<chrono::microseconds>(stop - ready);
    MyFile << "Overall," << duration.count() << endl;
}


    