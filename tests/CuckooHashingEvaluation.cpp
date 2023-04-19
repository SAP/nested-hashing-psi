#include <iostream>
#include <vector>
#include <string>
#include "mid_layer/DamgardJurikEnc.hpp"
#include "src/Common/Crypto/AddHomElGamalEnc.hpp"
#include "src/Common/Hashing/CuckooHashTable.hpp"
#include "src/Common/Hashing/HashUtils.hpp"
#include "primitives/DlogOpenSSL.hpp"
#include "primitives/HashOpenSSL.hpp"
#include "boost/program_options.hpp"
namespace po = boost::program_options;

#ifdef VERBOSE
#undef VERBOSE
#endif

int main(int argc, char *argv[])
{
    uint64_t maxmimumNumberOfRuns;
    size_t numberOfHashElements;
    uint64_t itemsPP;
    uint64_t numberOfCuckooHashFunctions;
    uint64_t stashSize;
    bool help;
    // Declare the supported options.
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h",po::bool_switch(&help), "produce help message")
        ("nElem", po::value<uint64_t>(&numberOfHashElements)->default_value(1048576), "Number of elements to hash") // 2 ^ 20
        ("nRuns", po::value<uint64_t>(&maxmimumNumberOfRuns)->default_value(1048576), "maximum Number of table creations")
        ("stash", po::value<uint64_t>(&stashSize)->default_value(2), "Stash Size")
        ("nCuckooHF", po::value<uint64_t>(&numberOfCuckooHashFunctions)->default_value(2), "Number Of Cuckoo hash functions")
        ("itemsPP", po::value<uint64_t>(&itemsPP)->default_value(1), "Number of items per Position");

    po::variables_map vm;
    po::store(parse_command_line(argc, argv, desc), vm);
    po::notify(vm); 

    if(help) {
        cout << desc << "\n";
        return 0;
    }
    cout << "Run Cuckoo Hashing evaluation (no combined tables)" << endl;
    uint64_t averageBinSize = numberOfHashElements; //No averag, s


    cout << "Generate plaintexts";
    uint64_t itemSeed = 4326418964;
    uint64_t hashSeed = 2350176483526;

    string fileName = "CT_nE_" + to_string(numberOfHashElements) + "_nR_" + to_string(maxmimumNumberOfRuns) + "_sts_" + to_string(stashSize) +
                       "_nCH_" + to_string(numberOfCuckooHashFunctions) +
                      + "_nPP_" +  to_string(itemsPP) + ".csv";



    cout << "Setup elements" << endl;
    boost::random::mt19937 mt(itemSeed);
    boost::random::uniform_int_distribution<uint64_t> randInt64;

    vector<biginteger> elems(numberOfHashElements);
    for (size_t i = 0; i < numberOfHashElements; i++)
    {
        elems[i] = randomBiginteger(mt, randInt64);

        #ifdef VERBOSE
            cout << elems[i] << endl;
        #endif
    }

    TabulationHashing hashfu = TabulationHashing(hashSeed, numberOfCuckooHashFunctions);
    vector<double> slackParams {1.0, 1.05, 1.1, 1.15, 1.2, 1.3, 1.4, 1.5, 2, 2.5, 3};
    vector<uint64_t> observedErrors(slackParams.size());
    
    cout << "Test and write results" << endl;

    ofstream opFile(fileName);

    for(size_t i = 0; i < observedErrors.size(); i++) {
        
        double tableSize = (slackParams[i] * averageBinSize) / (numberOfCuckooHashFunctions);
        uint64_t eachCuckooTableSize = (uint64_t) ceil(tableSize / itemsPP );  //Round up
        double effectiveSlackRatio = (eachCuckooTableSize*itemsPP*numberOfCuckooHashFunctions / ((double) numberOfHashElements));

        cout << "eachCuckooTableSize: " << eachCuckooTableSize << endl;
        cout << "itemsPP: " << itemsPP << endl;
        cout << "ExpectedRatio: " << slackParams[i] << endl;
        cout << "EffectiveRatio: " << effectiveSlackRatio << endl;

        for(size_t rC = 0; rC < maxmimumNumberOfRuns; rC++) {

            TabulationHashing hashfu = TabulationHashing(hashSeed, numberOfCuckooHashFunctions);
            CuckooHashTable hcT(hashfu, eachCuckooTableSize, numberOfCuckooHashFunctions, 0, stashSize, true, itemsPP);
            hashSeed++;

            #ifdef VERBOSE
            bool errFound = false; 
            #endif
            try {
                hcT.insertAll(elems);
            } catch (const runtime_error& e) {
                observedErrors[i] += 1;

                #ifdef VERBOSE
                errFound = true;
                #endif
            }

            #ifdef VERBOSE
            if(errFound) {
                cout << "Cuckoo Hashing error" << endl;
            } else {
                cout << "No error" << endl;
                for(auto& row : hcT.cuckooTable) {
                    for(int j = 0; j < row[0].size(); j++) { //Switched
                        for(int i = 0; i < row.size(); i++) {

                            cout << j << "," << i << ": " << row[i][j] << endl;
                        }
                        cout << "&" << endl;
                    }
                    cout << "&&" << endl;
                }
            }

            #endif
        }
        opFile << slackParams[i] << "," << effectiveSlackRatio << "," << observedErrors[i] << endl;
    }
}