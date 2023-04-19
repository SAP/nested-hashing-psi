/**
 * @file SimpleFHEPSIClient.cpp
 * 
 * @version 0.1
 *
 */
#include "SimpleFHEPSIClient.hpp"
#include "src/Common/DataInput/RandomDataInput.hpp"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

SimpleFHEPSIClient::SimpleFHEPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams) : PSIClient(dataIH, clientParams, protocolName()),
                                                                                                                             htParams(htParams)
{
}

void SimpleFHEPSIClient::runSetUpPhase()
{

    // Initialize Hashing

    resultSize = htParams.numberOfCuckooHashFunctions;
    uint64_t neededHfs = htParams.numberOfSimpleHashFunctions + htParams.numberOfCuckooHashFunctions;
    hashfunction = TabulationHashing(clientParams.hashSeed, neededHfs);

    PlaintextModulus n;
    if (clientParams.bitSize == 16)
    {
        n = 65537; // 2^16 + 1
    }
    else if (clientParams.bitSize == 32)
    {
        n = (4296540161); // 2^32 + 2^20 + 2^19 + 1
    }
    else if (clientParams.bitSize == 40)
    {
        n = (1099579260929); // 2^40 + 2^22 + 2^20 + 1
    }
    else if (clientParams.bitSize == 48)
    {
        n = (281474981953537); // 2^48 + 2^22 + 2^20 + 1
    }
    else
    {
        throw invalid_argument("Error: FHE can only support bit sizes 16 or 32.");
    }
    // Set CryptoContext
    if (clientParams.bgv)
    {
        lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> parameters;
        parameters.SetPlaintextModulus(n);
        parameters.SetMultiplicativeDepth(3);
        parameters.SetBatchSize(htParams.eachCuckooTableSize + 1);
        parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
        cryptoContext = GenCryptoContext(parameters);
    }
    else
    {
        lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(n);
        parameters.SetMultiplicativeDepth(3);
        parameters.SetBatchSize(htParams.eachCuckooTableSize + 1);
        parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
        cryptoContext = GenCryptoContext(parameters);
    }

    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    // cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Eval Sum Keys
    cryptoContext->EvalSumKeyGen(keyPair.secretKey, keyPair.publicKey);

    // Eval Automorphism Key Gen
    vector<int> rotateV(htParams.eachCuckooTableSize);
    for (size_t i = 0; i < rotateV.size(); i++)
    {

        rotateV[i] = -((int)i + 1);
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, rotateV, keyPair.publicKey);

    // Init hashing
    uint startingHashId = 0;
    uint64_t maxStashSize = 0;

    clientHashTable = make_shared<CuckooHashTable>(hashfunction,
                                                   htParams.eachSimpleTableSize, htParams.numberOfSimpleHashFunctions, startingHashId, maxStashSize,
                                                   htParams.simpleMultiTable);

#ifdef VERBOSE
    cout << "Send context and keys to server" << endl;
#endif
    sendContextAndKeys();
}

void SimpleFHEPSIClient::runOfflinePhase()
{

    clientHashTable->insertAll(clientSet);

    encryptedCuckooIndexMatrices = vector<vector<indexFHEVectorType *>>(clientHashTable->getNumberOfTables(),
                                                                        vector<indexFHEVectorType *>(htParams.eachSimpleTableSize));

    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        // Assumes Bin size 1 for client
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {

            biginteger &elem = clientHashTable->cuckooTable[i][0][j];
            if (elem == 0)
            {
                elem = 1;
            }
            indexFHEVectorType *indexMatrix = new indexFHEVectorType(htParams.numberOfCuckooHashFunctions);

            for (uint hfInd = htParams.numberOfSimpleHashFunctions;
                 hfInd < htParams.numberOfCuckooHashFunctions + htParams.numberOfSimpleHashFunctions;
                 hfInd++)
            {
                vector<int64_t> plainIndexVec(htParams.eachCuckooTableSize + 1);
                uint_fast64_t hashIndex = calculateHashIndex(hashfunction, elem, hfInd, htParams.eachCuckooTableSize);

                cout << "Hash index " << hfInd << ": " << hashIndex << endl;
                for (uint64_t vectorIndex = 0; vectorIndex < htParams.eachCuckooTableSize; vectorIndex++)
                {

                    if (vectorIndex == hashIndex && elem != 1)
                    {
                        plainIndexVec[vectorIndex] = 1;
                    }
                    else
                    {
                        plainIndexVec[vectorIndex] = 0;
                    }
                }

#ifdef VERBOSE
                cout << "Minus comp elem to enc: " << -((int64_t)elem) << endl;
#endif
                plainIndexVec[htParams.eachCuckooTableSize] = -((int64_t)elem);

                auto packedVec = cryptoContext->MakePackedPlaintext(plainIndexVec);
                (*indexMatrix)[hfInd - htParams.numberOfSimpleHashFunctions] = cryptoContext->Encrypt(keyPair.secretKey, packedVec);
            }

            // Create Index Vector
            encryptedCuckooIndexMatrices[i][j] = indexMatrix;
        }
    }
}
void SimpleFHEPSIClient::runOnlinePhase()
{

    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {

            sendIndexMatrix(encryptedCuckooIndexMatrices[i][j]);
        }
    }

    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {

            bool included = receiveResult();

            if (included)
            {
                intersectionCalculated.push_back(clientHashTable->cuckooTable[i][0][j]);
            }
        }
    }
}

void SimpleFHEPSIClient::sendIndexMatrix(indexFHEVectorType *indexMatrix)
{

    for (size_t i = 0; i < indexMatrix->size(); i++)
    {

        auto cryptoSerStream = std::ostringstream();
        lbcrypto::Serial::Serialize((*indexMatrix)[i], cryptoSerStream, defaultSerType);
        channel->writeWithSize(cryptoSerStream.str());
    }
}

void SimpleFHEPSIClient::sendContextAndKeys()
{

    // Serialize cryptocontext
    auto cryptoSerStream = std::ostringstream();
    lbcrypto::Serial::Serialize(cryptoContext, cryptoSerStream, defaultSerType);
    channel->writeWithSize(cryptoSerStream.str());
#ifdef VERBOSE
    std::cout << "The cryptocontext has been sent:" << cryptoSerStream.str().size() << std::endl;
#endif

    // Sample Program: Step 3 - Encryption

    // Serialize public key
    auto pKSerStream = std::ostringstream();
    lbcrypto::Serial::Serialize(keyPair.publicKey, pKSerStream, defaultSerType);
    channel->writeWithSize(pKSerStream.str());
#ifdef VERBOSE
    std::cout << "The public key has been sent:" << pKSerStream.str().size() << std::endl;
#endif

    // Serialize Sum Keys

    auto sKSerStream = std::ostringstream();
    cryptoContext->SerializeEvalSumKey(sKSerStream, defaultSerType);
    channel->writeWithSize(sKSerStream.str());

#ifdef VERBOSE
    std::cout << "The sum keys have been sent:" << sKSerStream.str().size() << std::endl;
#endif

    // Serialize Automorphism Keys

    auto autoKSerStream = std::ostringstream();
    cryptoContext->SerializeEvalAutomorphismKey(autoKSerStream, defaultSerType);
    channel->writeWithSize(autoKSerStream.str());

#ifdef VERBOSE
    std::cout << "The automorphism keys have been sent:" << autoKSerStream.str().size() << std::endl;
#endif
}

bool SimpleFHEPSIClient::receiveResult()
{
    bool found = false;
    for (int i = 0; i < resultSize; i++)
    {
        lbcrypto::Ciphertext<FHEEncType> ciphertext;
        vector<unsigned char> cipherVector;
        channel->readWithSizeIntoVector(cipherVector);
        auto ctSS = std::istringstream(std::string(cipherVector.begin(), cipherVector.end()));
        lbcrypto::Serial::Deserialize(ciphertext, ctSS, defaultSerType);
        lbcrypto::Plaintext plaintext;
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &plaintext);
        plaintext->SetLength(htParams.maxItemsPerPosition);
        for (auto &plain : plaintext->GetPackedValue())
        {
            cout << plain << endl;
            if (plain == 0)
            {
                found = true;
                break;
            }
        }
    }
    return found;
}