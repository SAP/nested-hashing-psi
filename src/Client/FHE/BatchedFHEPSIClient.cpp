#include "BatchedFHEPSIClient.hpp"
#include "src/Common/DataInput/RandomDataInput.hpp"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

BatchedFHEPSIClient::BatchedFHEPSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, HashTableParameter &htParams) : PSIClient(dataIH, clientParams, protocolName()),
                                                                                                                               htParams(htParams)
{
}

void BatchedFHEPSIClient::runSetUpPhase()
{

    // Initialize Hashing

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

    // Choose multplicative depth depending on bin size
    uint32_t depth;
    if (htParams.eachCuckooTableSize < 500)
    {
        depth = 3;
    }
    else if (htParams.eachCuckooTableSize < 5000)
    {
        depth = 5;
    }
    else
    {
        depth = 10;
    }

    // Set CryptoContext
    if (clientParams.bgv)
    {
        lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> parameters;
        parameters.SetRingDim(16384);
        parameters.SetPlaintextModulus(n);
        parameters.SetMultiplicativeDepth(depth);
        parameters.SetBatchSize(htParams.eachCuckooTableSize * htParams.numberOfSimpleHashFunctions);
        parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
        cryptoContext = GenCryptoContext(parameters);
    }
    else
    {
        lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> parameters;
        parameters.SetRingDim(16384);
        parameters.SetPlaintextModulus(n);
        parameters.SetMultiplicativeDepth(depth);
        parameters.SetBatchSize(htParams.eachSimpleTableSize * htParams.numberOfSimpleHashFunctions);
        parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
        cryptoContext = GenCryptoContext(parameters);
    }

    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    // cryptoContext->Enable(ADVANCEDSHE);

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Eval Mult Keys
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

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

void BatchedFHEPSIClient::runOfflinePhase()
{

    clientHashTable->insertAll(clientSet);

    // Transform to encryptable vectors

    vector<vector<vector<int64_t>>> plainBatchedIndexMatrix(htParams.numberOfCuckooHashFunctions,
                                                            vector<vector<int64_t>>(htParams.eachCuckooTableSize,
                                                                                    vector<int64_t>(htParams.eachSimpleTableSize * htParams.numberOfSimpleHashFunctions)));

    vector<int64_t> plainBatchedMinusElemTable(htParams.eachSimpleTableSize * htParams.numberOfSimpleHashFunctions);

    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {

            size_t currentTableCount = i * htParams.eachSimpleTableSize + j;

            biginteger &elem = clientHashTable->cuckooTable[i][0][j];
            if (elem == 0)
            {
                plainBatchedMinusElemTable[currentTableCount] = 1;
            }
            else
            {

#ifdef VERBOSE
                cout << "Minus comp elem to enc: " << -((int64_t)elem) << endl;
#endif
                plainBatchedMinusElemTable[currentTableCount] = -((int64_t)elem); // cast to int64_t for openFHE

                for (uint hfInd = htParams.numberOfSimpleHashFunctions;
                     hfInd < htParams.numberOfCuckooHashFunctions + htParams.numberOfSimpleHashFunctions;
                     hfInd++)
                {
                    uint_fast64_t hashIndex = calculateHashIndex(hashfunction, elem, hfInd, htParams.eachCuckooTableSize);

                    // Set correct index bit
                    plainBatchedIndexMatrix[hfInd - htParams.numberOfSimpleHashFunctions][hashIndex][currentTableCount] = 1;
                }
            }
        }
    }

    // Encrypt all

    auto plainEl = cryptoContext->MakePackedPlaintext(plainBatchedMinusElemTable);
    encryptedMinusElements = cryptoContext->Encrypt(keyPair.secretKey, plainEl);

    batchedEncryptedIndexMatrix = vector<vector<lbcrypto::Ciphertext<FHEEncType>>>(htParams.numberOfCuckooHashFunctions,
                                                                                   vector<lbcrypto::Ciphertext<FHEEncType>>(htParams.eachCuckooTableSize));

    for (uint i = 0; i < htParams.numberOfCuckooHashFunctions; i++)
    {
        for (size_t j = 0; j < htParams.eachCuckooTableSize; j++)
        {
            auto plainT = cryptoContext->MakePackedPlaintext(plainBatchedIndexMatrix[i][j]);
            batchedEncryptedIndexMatrix[i][j] = cryptoContext->Encrypt(keyPair.secretKey, plainT);
        }
    }
}
void BatchedFHEPSIClient::runOnlinePhase()
{

    sendEncryptedMinusElements();
    sendIndexMatrix();
    receiveAndStoreResult();

    // Extract Results
    for (uint i = 0; i < clientHashTable->getNumberOfTables(); i++)
    {
        for (size_t j = 0; j < clientHashTable->cuckooTable[i][0].size(); j++)
        {
            size_t currentTableCount = i * htParams.eachSimpleTableSize + j;
            for (size_t binIndex = 0; binIndex < htParams.maxItemsPerPosition; binIndex++)
            {
                if (batchedDecryptedResult[binIndex][currentTableCount] == 0)
                {
                    intersectionCalculated.push_back(clientHashTable->cuckooTable[i][0][j]);
                    break;
                }
            }
        }
    }
}

void BatchedFHEPSIClient::sendEncryptedMinusElements()
{

    auto cryptoSerStream = std::ostringstream();
    lbcrypto::Serial::Serialize(encryptedMinusElements, cryptoSerStream, defaultSerType);
    channel->writeWithSize(cryptoSerStream.str());
}

void BatchedFHEPSIClient::sendIndexMatrix()
{

    for (uint i = 0; i < htParams.numberOfCuckooHashFunctions; i++)
    {
        for (size_t j = 0; j < htParams.eachCuckooTableSize; j++)
        {
            auto cryptoSerStream = std::ostringstream();
            lbcrypto::Serial::Serialize(batchedEncryptedIndexMatrix[i][j], cryptoSerStream, defaultSerType);
            channel->writeWithSize(cryptoSerStream.str());
        }
    }
}

void BatchedFHEPSIClient::sendContextAndKeys()
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

    // Serialize Mult Keys

    auto mKSerStream = std::ostringstream();
    cryptoContext->SerializeEvalMultKey(mKSerStream, defaultSerType);
    channel->writeWithSize(mKSerStream.str());

#ifdef VERBOSE
    std::cout << "The mult keys have been sent:" << mKSerStream.str().size() << std::endl;
#endif
}

void BatchedFHEPSIClient::receiveAndStoreResult()
{

    batchedDecryptedResult = vector<vector<int64_t>>(htParams.maxItemsPerPosition, vector<int64_t>());
    for (size_t binIndex = 0; binIndex < htParams.maxItemsPerPosition; binIndex++)
    {
        lbcrypto::Ciphertext<FHEEncType> ciphertext;
        vector<unsigned char> cipherVector;
        channel->readWithSizeIntoVector(cipherVector);
        auto ctSS = std::istringstream(std::string(cipherVector.begin(), cipherVector.end()));
        lbcrypto::Serial::Deserialize(ciphertext, ctSS, defaultSerType);
        lbcrypto::Plaintext plaintext;
        cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &plaintext);
        plaintext->SetLength(htParams.eachSimpleTableSize * htParams.numberOfSimpleHashFunctions);
        batchedDecryptedResult[binIndex] = plaintext->GetPackedValue();
    }
}