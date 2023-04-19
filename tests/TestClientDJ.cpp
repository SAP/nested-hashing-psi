#include <iostream>
#include <vector>
#include <string>
#include "mid_layer/DamgardJurikEnc.hpp"
#include "comm/Comm.hpp"
using namespace std;



int main(int argc, char* argv[]) {

    int array_size = atoi(argv[1]); //hyperparameter
    int key_length = atoi(argv[2]);

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
    DamgardJurikEnc encryptor;

    DJKeyGenParameterSpec spec(key_length,40);
    auto pair = encryptor.generateKey(&spec);
    encryptor.setKey(pair.first,pair.second);
    encryptor.setLengthParameter(1);
    cout << "Send public key to server" <<endl;
    auto pk = ((DamgardJurikPublicKey*) (pair.first.get()))->toString();
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
    

    channel->readWithSizeIntoVector(cipherVector);
    BigIntegerCiphertext* bICiphertext = new BigIntegerCiphertext((biginteger) 1); // missing default
    bICiphertext->initFromByteVector(cipherVector);
    auto cipherText = encryptor.reconstructCiphertext(bICiphertext);

    auto decryptedPlaintext = encryptor.decrypt(cipherText.get());
    biginteger plainInt = ((BigIntegerPlainText*) (decryptedPlaintext.get()))->getX();
    cout << "Receive Result" << endl;
    cout << plainInt.str() << "\n";

    bool correct1 = (b == 0) && (plainInt == 0);
    bool correct2 = (b == 1) && (plainInt != 0);

    if(correct1 || correct2) {
        cout << "Congratulations, expected and calculated values match.";
        return(0);
    } else {
        cerr << "Expected and calculated values do not match!";
        return(-1);
    }
}