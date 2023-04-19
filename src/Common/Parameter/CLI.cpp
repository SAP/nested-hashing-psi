/**
 * @file CLI.cpp
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * 
 */
#include "CLI.hpp"
#include "boost/program_options.hpp"
namespace po = boost::program_options;
/**
 * @brief Method to parse command line arguments
 * 
 * @param argc 
 * @param argv 
 * @return pair<bool, pair<PSIParameter,HashTableParameter>> First pait entry (bool) indicates if PSI protocol should be executed (e.g., no -h)
 */
pair<bool, pair<PSIParameter,HashTableParameter>> readParameters(int argc, char *argv[]) {


    size_t serverSetSize;
    size_t clientSetSize;
    size_t intersectionSetSize;
    size_t numberOfThreads;
    uint64_t eachSimpleTableSize;
    uint64_t eachCuckooTableSize;
    uint64_t serverStashSize;
    uint64_t numberOfSimpleHashFunctions;
    uint64_t numberOfCuckooHashFunctions;
    bool combinedSimpleTable;
    bool combinedCuckooTable;
    std::string ip;
    int port;
    bool verbose;
    bool exportPerf;
    bool precomp;
    bool fhe;
    uint64_t hashSeed;
    uint64_t itemSeed;
    uint64_t maxItemsPerPosition;
    std::string curveName;
    uint64_t bitSize;
    bool bgv;
    bool batched;

    // Declare the supported options.
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "produce help message")
        ("verbose,v", po::bool_switch(&verbose), "Verbose (NOT yet supported)")
        ("perf,p", po::bool_switch(&exportPerf), "Export performance measures")
        ("precomp,P", po::bool_switch(&precomp), "Use precomputation")
        ("fhe,F", po::bool_switch(&fhe), "Use FHE")
        ("nThreads,t", po::value<size_t>(&numberOfThreads)->default_value(1), "Number Of server PIE threads (+ 2)")
        ("combinedSimpleTable,s", po::bool_switch(&combinedSimpleTable), "Use combined Cuckoo version for client")
        ("combinedCuckooTable,c", po::bool_switch(&combinedCuckooTable), "Use combined Cuckoo version for server")
        ("serverSetSize,S", po::value<size_t>(&serverSetSize)->default_value(400), "Size of the server set")
        ("clientSetSize,C", po::value<size_t>(&clientSetSize)->default_value(2), "Size of the client set")
        ("intersectionSetSize,I", po::value<size_t>(&intersectionSetSize)->default_value(2), "Size of the intersection set")
        ("eachSimpleTableSize,e", po::value<uint64_t>(&eachSimpleTableSize)->default_value(4), "Size of each simple table")
        ("eachCuckooTableSize,E", po::value<uint64_t>(&eachCuckooTableSize)->default_value(10), "Size of each Cuckoo table")
        ("stash", po::value<uint64_t>(&serverStashSize)->default_value(0), "serverStashSize")
        ("nSimpleHF,k", po::value<uint64_t>(&numberOfSimpleHashFunctions)->default_value(2), "Number Of simple hash functions")
        ("nCuckooHF,K", po::value<uint64_t>(&numberOfCuckooHashFunctions)->default_value(2), "Number Of Cuckoo hash functions")
        ("maxPP,b", po::value<uint64_t>(&maxItemsPerPosition)->default_value(10), "maximum items per Cuckoo table position on server-side")
        ("bitSize,B", po::value<uint64_t>(&bitSize)->default_value(32), "Bit size of input elements, FHE supports 16 or 32 bit")
        ("seed", po::value<uint64_t>(&hashSeed)->default_value(987654321), "hashSeed")
        ("itemSeed", po::value<uint64_t>(&itemSeed)->default_value(123456789), "itemSeed")
        ("ip", po::value<std::string>(&ip)->default_value("127.0.0.1"),"ip adress")
        ("port", po::value<int>(&port)->default_value(8000), "ip port")
        ("curve", po::value<string>(&curveName)->default_value("P-256"), "Curve for ElGamal based PSI, not used for FHE")
        ("bgv", po::bool_switch(&bgv), "Use BGV instead of BFV, only used for FHE")
        ("batched", po::bool_switch(&batched), "Use batched FHE version, only used for FHE");
        
    po::variables_map vm;
    po::store(parse_command_line(argc, argv, desc), vm);
    po::notify(vm);    

    const HashTableParameter parsedHTParams(eachSimpleTableSize,
                           eachCuckooTableSize,
                           serverStashSize,
                           numberOfSimpleHashFunctions,
                           numberOfCuckooHashFunctions,
                           !combinedSimpleTable,
                           !combinedCuckooTable,
                           maxItemsPerPosition);

    PSIParameter parsedParams(serverSetSize,
                           clientSetSize,
                           intersectionSetSize,
                           hashSeed,
                           itemSeed,
                           ip,
                           port,
                           verbose,
                           exportPerf,
                           numberOfThreads,
                           precomp,
                           fhe,
                           bitSize,
                           curveName,
                           bgv,
                           batched);

    if (vm.count("help")) {
        cout << desc << "\n";
        return make_pair(false, make_pair(parsedParams, parsedHTParams));
    } 

    return make_pair(true, make_pair(parsedParams, parsedHTParams));
}