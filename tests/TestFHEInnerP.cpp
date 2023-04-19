#include "openfhe.h"
#include "openfhecore.h"
#include <iostream>

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
using namespace lbcrypto;

#ifndef defaultSerType
    #define defaultSerType lbcrypto::SerType::BINARY
#endif
int main(int argc, char *argv[])
{
    // Sample Program: Step 1 - Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters; 
    PlaintextModulus t(65537);   
    //PlaintextModulus t((1UL << 32) + (1UL << 20) + (1UL<< 19) + 1);   
    parameters.SetPlaintextModulus(t);
    parameters.SetMultiplicativeDepth(3);
    //parameters.SetBatchSize(8000);

    //parameters.SetFirstModSize(60);
    //parameters.SetScalingModSize(60);
    
    parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    //cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    
    auto params = cryptoContext->GetCryptoParameters();

    std::cout << "p = " << params->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << params->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << params->GetElementParams()->GetModulus().GetMSB() << std::endl;
    std::cout << "Modulus = " << cryptoContext->GetModulus() << std::endl;
    std::cout << "Ring Dim = " << cryptoContext->GetRingDimension() << std::endl;    
    // Sample Program: Step 2 - Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();;


    //Eval Sum Keys
    cryptoContext->EvalSumKeyGen(keyPair.secretKey, keyPair.publicKey);

    //Eval Automorphism Key Gen
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {-1, -2, -3, -4});

    // Serialize cryptocontext
    auto cryptoSerStream = std::ostringstream();
    Serial::Serialize(cryptoContext, cryptoSerStream, defaultSerType);
    std::cout << "The cryptocontext has been serialized: " << cryptoSerStream.str() <<  std::endl;
    auto sS = std::istringstream(cryptoSerStream.str());

    CryptoContext<DCRTPoly> cryptoContext2;
    Serial::Deserialize(cryptoContext2, sS, defaultSerType);
    std::cout << "The cryptocontext has been deserialized. " <<  std::endl;

    // Sample Program: Step 3 - Encryption

    // Serialize public key
    auto pKSerStream = std::ostringstream();
    Serial::Serialize(keyPair.publicKey, pKSerStream, defaultSerType);
    std::cout << "The public key has been serialized: " << pKSerStream.str().size() <<  std::endl;
    auto pKSS = std::istringstream(pKSerStream.str());
    PublicKey<DCRTPoly> pKDe;
    Serial::Deserialize(pKDe, pKSS, defaultSerType);
    //std::cout << "Public Key valid: " << Serial::SerializeToString(pKDe) << std::endl;

    // First plaintext vector is encoded
    std::vector<int64_t> vectorOfInts1 = {0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 123};

    // Second plaintext vector is encoded
    std::vector<int64_t> vectorOfInts2 = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 654};
    // Third plaintext vector is encoded
    std::vector<int64_t> vectorOfInts3 = {-653 + 65537, 243, 65536, -123, 432, 43, 25, 643, 31, 324, 31, 1};

    size_t additionalEntries = 0;
    for(size_t k = 0; k < additionalEntries; k++) {
        vectorOfInts1.push_back(0);
        vectorOfInts2.push_back(0);
        vectorOfInts3.push_back(14241);
    }

    Plaintext plaintext1               = cryptoContext2->MakePackedPlaintext(vectorOfInts1);
    Plaintext plaintext2               = cryptoContext2->MakePackedPlaintext(vectorOfInts2);
    Plaintext plaintext3               = cryptoContext2->MakePackedPlaintext(vectorOfInts3);

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext2->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext2->Encrypt(keyPair.publicKey, plaintext2);
    auto ciphertext3 = cryptoContext2->Encrypt(keyPair.publicKey, plaintext3);

    // Sample Program: Step 4 - Evaluation

    //Inner Product
    auto cipherV = {cryptoContext2->EvalInnerProduct(ciphertext1, plaintext3, vectorOfInts1.size()),
                    cryptoContext2->EvalInnerProduct(ciphertext2, plaintext3, vectorOfInts1.size()),
                    cryptoContext2->EvalInnerProduct(ciphertext1, plaintext3, vectorOfInts1.size()),
                    cryptoContext2->EvalInnerProduct(ciphertext2, plaintext3, vectorOfInts1.size()),
                    };

    auto cipherR = cryptoContext2->EvalMerge(cipherV);


    Plaintext plaintextInnerR;
    cryptoContext2->Decrypt(keyPair.secretKey, cipherR, &plaintextInnerR);
    plaintextInnerR->SetLength(6);

    std::cout << "InnerP: " << plaintextInnerR << std::endl;

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    return 0;
}
