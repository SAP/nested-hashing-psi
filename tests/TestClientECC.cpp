#include <iostream>
#include <vector>
#include <string>
#include "src/Common/Crypto/AddHomElGamalEnc.hpp"
#include "src/PSIConfigs.h"
#include "comm/Comm.hpp"
using namespace std;



int main(int argc, char* argv[]) {

    int array_size = atoi(argv[1]); //hyperparameter
    string curve_name(argv[2]);

    string ip = "127.0.0.1";
    int port = 8000;

    SocketPartyData me, other;
    boost::asio::io_service io_service;

    me = SocketPartyData(boost_ip::address::from_string(ip), port);
    cout<<"my port = "<<port << endl;
    other = SocketPartyData(boost_ip::address::from_string(ip), port + 1);
    cout<<"other port = "<<port + 1 <<endl;

    shared_ptr<CommParty> channel = make_shared<CommPartyTCPSynced>(io_service, me, other);
    // connect to party one
    channel->join(500, 5000);
    cout<<"channel established"<<endl;

        
    cout<<"Generate element to compare"<<endl;
    uint64_t seed = 1498165861356;
    boost::random::mt19937 mt(seed);     
    boost::random::uniform_int_distribution<uint64_t> randInt64;

    int elem_index = atoi(argv[3]) % array_size; // CLI index

    uint64_t elem;

    int b = atoi(argv[4]) % 2; //CLI bit indicating if the outputs shall differ (i.e. Server has a different item at index i)
    
    for(int i = 0; i < elem_index; i++) {
        elem = randInt64(mt);
    }
    if (b == 0) {
        elem = randInt64(mt);
    }

    cout << "Element to compare: \t" << elem << endl;
    shared_ptr<DlogEllipticCurve> dlog = make_shared<OpenSSLDlogECF2m>(OpenSSLCurveDir, curve_name); 
    cout << "Generator: " << dlog->getGenerator()->generateSendableData()->toString() << endl; 
    AddHomElGamalEnc encryptor(dlog);

    
    auto pair = encryptor.generateKey();
    encryptor.setKey(pair.first,pair.second);


    cout << "Send public key to server" <<endl;
    auto pk = ((ElGamalPublicKey*) (pair.first.get()))->generateSendableData()->toString();
    cout << "Public Key: " << pk << endl;
    channel->writeWithSize(pk);
 

    cout << "Send index vector" << endl;
    shared_ptr<BigIntegerPlainText> ct;
    for(int index = 0; index < array_size; index++) {
        if(index == elem_index) {
            
            ct = make_shared<BigIntegerPlainText>(1);

        } else {
            ct = make_shared<BigIntegerPlainText>(0);
        }
        shared_ptr<AsymmetricCiphertext> cipherIndex = encryptor.encrypt(ct);

        string sendCipher = cipherIndex->generateSendableData()->toString();

        //cout << "Send Ciphertext" << sendCipher << endl;
        channel->writeWithSize(sendCipher);

    }

    cout << "Send Cipher" << endl;
    shared_ptr<BigIntegerPlainText> plainT = make_shared<BigIntegerPlainText>(elem);

    shared_ptr<AsymmetricCiphertext> cipherToComp = encryptor.encrypt(plainT);

    string sendCipher = cipherToComp ->generateSendableData()->toString();

    channel->writeWithSize(sendCipher);

    vector<unsigned char> cipherVector;
    
    cout << "Read Cipher" << endl;
    channel->readWithSizeIntoVector(cipherVector);
    auto cipherText = encryptor.reconstructCiphertext(cipherVector);

    cout << "Encrypted Value Received" << cipherText->generateSendableData()->toString() << endl;

    auto decryptedPlaintext = encryptor.decrypt(cipherText.get());
    string plainDecrypted = decryptedPlaintext->generateSendableData()->toString();
    string identity = (dlog->getIdentity()->generateSendableData()->toString());
    bool equals = plainDecrypted == identity;

    cout << "Identity" << endl;
    cout << identity << "\n";
    
    cout << "Decrypted" << endl;
    cout << plainDecrypted << "\n";

    cout << "Receive Result" << endl;
    cout << equals << "\n";

    bool correct1 = (b == 0) && equals;
    bool correct2 = (b == 1) && !equals;

    if(correct1 || correct2) {
        cout << "Congratulations, expected and calculated values match.";
        return(0);
    } else {
        cerr << "Expected and calculated values do not match!";
        return(-1);
    }
}