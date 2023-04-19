#include <iostream>
#include <vector>
#include <string>
#include "mid_layer/DamgardJurikEnc.hpp"

int main()
{
    cout << "Test 1: DamgardJurik Additive Homomorphic Encryption \n";
    cout << "TestCase: Encrypt 0 and 1, add it up and multiply by hundred:\n";
    cout << "Calculated Value: \t";

    int expectedSolution = 100;
    // Let's encrypt the message

    DamgardJurikEnc encryptor;
    encryptor.setLengthParameter(1);
    DJKeyGenParameterSpec spec(128,40);
    auto pair = encryptor.generateKey(&spec);
    encryptor.setKey(pair.first,pair.second);
    const shared_ptr<BigIntegerPlainText> one(new BigIntegerPlainText((biginteger) 1));
    const shared_ptr<BigIntegerPlainText> zero(new BigIntegerPlainText((biginteger) 0));

    shared_ptr<AsymmetricCiphertext> oneCipher = encryptor.encrypt(one);
    shared_ptr<AsymmetricCiphertext> zeroCipher = encryptor.encrypt(zero);

    biginteger oneHundred(100);
    auto addOneZeroCipher = encryptor.add(oneCipher.get(), zeroCipher.get());
    auto mult100Cipher = encryptor.multByConst(addOneZeroCipher.get(), oneHundred);
    
    auto decryptedPlaintext = encryptor.decrypt(mult100Cipher.get());
    biginteger plainInt = ((BigIntegerPlainText*) (decryptedPlaintext.get()))->getX();

    cout << plainInt.str() << "\n";
    cout << "Expected Value:\t\t" << expectedSolution << "\n";

    if(plainInt != expectedSolution) {
        cerr << "Expected and calculated values do not match!";
        return(-1);
    } else {
        cout << "Congratulations, expected and calculated values match.";
    }

}