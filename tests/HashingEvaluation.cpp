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
#include "boost/program_options.hpp"
namespace po = boost::program_options;


int main(int argc, char *argv[])
{
    uint64_t maxmimumNumberOfRuns;
    size_t numberOfHashElements;
    uint64_t eachSimpleTableSize;
    double itemPPfrac;
    uint64_t numberOfSimpleHashFunctions;
    uint64_t numberOfCuckooHashFunctions;
    uint64_t serverStashSize;
    bool help;
    // Declare the supported options.
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h",po::bool_switch(&help), "produce help message")
        ("nElem", po::value<uint64_t>(&numberOfHashElements)->default_value(1048576), "Number of elements to hash") // 2 ^ 20
        ("nRuns", po::value<uint64_t>(&maxmimumNumberOfRuns)->default_value(1048576), "maximum Number of table creations")
        ("eachSimpleTableSize", po::value<uint64_t>(&eachSimpleTableSize)->default_value(128), "Size of each simple table")
        ("stash", po::value<uint64_t>(&serverStashSize)->default_value(2), "Stash Size")
        ("nSimpleHF", po::value<uint64_t>(&numberOfSimpleHashFunctions)->default_value(3), "Number Of simple hash functions")
        ("nCuckooHF", po::value<uint64_t>(&numberOfCuckooHashFunctions)->default_value(2), "Number Of Cuckoo hash functions")
        ("itemPPfrac", po::value<double>(&itemPPfrac)->default_value(1), "fraction (div by 1000) between table size and items per Position");

    po::variables_map vm;
    po::store(parse_command_line(argc, argv, desc), vm);
    po::notify(vm); 

    if(help) {
        cout << desc << "\n";
        return 0;
    }
    cout << "Run Nested Cuckoo Hashing evaluation (no combined tables)" << endl;
    uint64_t averageBinSize = (numberOfHashElements + eachSimpleTableSize - 1) / eachSimpleTableSize; //Round up


    cout << "Generate plaintexts";
    uint64_t itemSeed = 4326418964;
    uint64_t hashSeed = 2350176483526;

    string fileName = "NCT_nE_" + to_string(numberOfHashElements) + "_nR_" + to_string(maxmimumNumberOfRuns) + 
                      "_eSs_" + to_string(eachSimpleTableSize) + "_sts_" + to_string(serverStashSize) +
                      "_nSH_" + to_string(numberOfSimpleHashFunctions) + "_nCH_" + to_string(numberOfCuckooHashFunctions) +
                      + "_frac_" +  to_string(itemPPfrac) + ".csv";



    cout << "Setup elements" << endl;
    boost::random::mt19937 mt(itemSeed);
    boost::random::uniform_int_distribution<uint64_t> randInt64;

    vector<biginteger> elems(numberOfHashElements);
    for (size_t i = 0; i < numberOfHashElements; i++)
    {
        elems[i] = randomBiginteger(mt, randInt64);
    }

    TabulationHashing hashfu = TabulationHashing(hashSeed, numberOfSimpleHashFunctions + numberOfCuckooHashFunctions);
    vector<double> slackParams {1.0, 1.05, 1.1, 1.15, 1.2, 1.25, 1.3, 1.35, 1.4};
    vector<uint64_t> observedErrors(slackParams.size());
    
    cout << "Test and write results" << endl;

    ofstream opFile(fileName);

    for(size_t i = 0; i < observedErrors.size(); i++) {
        
        double tableSize = (slackParams[i] * averageBinSize) / (numberOfCuckooHashFunctions);
        double sqrtTableSize = sqrt(tableSize);
        double itemPPfracFloatRoot = sqrt(itemPPfrac);
        uint64_t eachCuckooTableSize = (uint64_t) ceil(sqrtTableSize * itemPPfracFloatRoot );  //Round up
        uint64_t itemsPP = (uint64_t) ceil(sqrtTableSize / itemPPfracFloatRoot);
        double effectiveSlackRatio = (eachCuckooTableSize*itemsPP*numberOfCuckooHashFunctions / ((double) numberOfHashElements));

        cout << "eachTableSize: " << tableSize << endl;
        cout << "sqrtTableSize: " << sqrtTableSize << endl;
        cout << "eachCuckooTableSize: " << eachCuckooTableSize << endl;
        cout << "itemsPP: " << itemsPP << endl;
        cout << "ExpectedRatio: " << slackParams[i] << endl;
        cout << "EffectiveRatio: " << effectiveSlackRatio << endl;

        for(size_t rC = 0; rC < maxmimumNumberOfRuns; rC++) {

            TabulationHashing hashfu = TabulationHashing(hashSeed, numberOfSimpleHashFunctions + numberOfCuckooHashFunctions);
            HierarchicalCuckooHashTable hcT(hashfu, eachSimpleTableSize, eachCuckooTableSize, serverStashSize,
                                numberOfSimpleHashFunctions, numberOfCuckooHashFunctions, true, true, itemsPP);
            hashSeed++;
            try {
                hcT.insertAll(elems);
            } catch (const runtime_error& e) {
                observedErrors[i] += 1;
            }
        }
        opFile << slackParams[i] << "," << effectiveSlackRatio << "," << observedErrors[i] << endl;
    }
}