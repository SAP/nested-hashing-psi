/**
 * @file PSIClient.hpp
 * 
 * @version 0.1
 *
 */
#pragma once
#include <chrono>
#include <fstream>
#include <ctime>
#include "comm/Comm.hpp"
#include <boost/thread/thread.hpp>
#include "src/Common/DataInput/DataInputHandler.hpp"
#include "src/Common/Parameter/PSIParameter.hpp"
#include "src/Common/Utils.hpp"
/**
 * @brief Abstract PSIClient object. Handles data i/o, communication and evaluation measurements.
 *
 */
class PSIClient
{

private:
protected:
    DataInputHandler &dataIH; // To test if sets matches
    PSIParameter &clientParams;
    std::vector<biginteger> &clientSet;
    shared_ptr<CommParty> channel;
    vector<biginteger> intersectionCalculated;
    boost::asio::io_service io_service;
    string protocolName;
    // boost::thread t;
    string exportFileName;

    void connectToServer()
    {
        // t = boost::thread(boost::bind(&boost::asio::io_service::run, &io_service));
        auto client = SocketPartyData(boost_ip::address::from_string(clientParams.ip), clientParams.port);
        auto server = SocketPartyData(boost_ip::address::from_string(clientParams.ip), clientParams.port + 1);
        channel = make_shared<CommPartyTCPSynced>(io_service, client, server, 1);
        channel->join(500, 5000000);
    }

    void closeConnection()
    {
        io_service.stop();
        // t.join();
    }

    void readPhaseOverSignal()
    {
        vector<unsigned char> signal;
        channel->readWithSizeIntoVector(signal);
    }

public:
    PSIClient(DataInputHandler &dataIH, PSIParameter &clientParams, string protocolName)
        : dataIH(dataIH), clientParams(clientParams), clientSet(dataIH.getClientSet()), protocolName(protocolName)
    {

        exportFileName = "MClient_CS_" + std::to_string(clientParams.clientSetSize) + "_SS_" + std::to_string(clientParams.serverSetSize) + "_P_" + protocolName + "_T_" + std::to_string(clientParams.numberOfThreads);

        std::time_t tTime = std::time(nullptr);
        char timeStr[80];
        std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d", std::localtime(&tTime));
        exportFileName += "_" + string(timeStr) + ".csv";
    }
    virtual void runSetUpPhase() = 0;
    virtual void runOfflinePhase() = 0;
    virtual void runOnlinePhase() = 0;

    void run()
    {

        cout << "Run " << protocolName << endl;
#ifdef VERBOSE
        cout << "Intersection expected:" << endl;
        for (biginteger &interElem : dataIH.getIntersectionSet())
        {
            cout << interElem << endl;
        }
        cout << "Expection END" << endl;
#endif
        cout << "Connect to server" << endl;
        connectToServer();
        cout << "Run Setup" << endl;
        chrono::steady_clock::time_point end;
        chrono::steady_clock::time_point begin = chrono::steady_clock::now();
        runSetUpPhase();
        readPhaseOverSignal();
        end = chrono::steady_clock::now();
        auto setUpTime = chrono::duration_cast<chrono::microseconds>(end - begin).count();
        cout << "Set up time = " << setUpTime << "[µs]" << endl;
        PSIMeasurement setUpM(setUpTime, channel->bytesIn, channel->bytesOut);
        channel->bytesIn = 0; // TODO: Care if used by other (communication thread)
        channel->bytesOut = 0;

        cout << "Run Offline" << endl;
        begin = chrono::steady_clock::now();
        runOfflinePhase();

        readPhaseOverSignal();
        end = chrono::steady_clock::now();
        auto offlineTime = chrono::duration_cast<chrono::microseconds>(end - begin).count();
        cout << "Offline time = " << offlineTime << "[µs]" << endl;
        PSIMeasurement offlineM(offlineTime, channel->bytesIn, channel->bytesOut);
        channel->bytesIn = 0; // TODO: Care if used by other (communication thread)
        channel->bytesOut = 0;

        cout << "Run Online" << endl;
        begin = chrono::steady_clock::now();
        runOnlinePhase();
        end = chrono::steady_clock::now();
        auto onlineTime = chrono::duration_cast<chrono::microseconds>(end - begin).count();
        cout << "Online time = " << onlineTime << "[µs]" << endl;
        PSIMeasurement onlineM(onlineTime, channel->bytesIn, channel->bytesOut);
        closeConnection();

        if (intersectionMatches())
        {
            cout << "Set matches!" << endl;
            if (clientParams.exportPerformance)
            {
                cout << "Export perfs" << endl;
                exportMeasurements(setUpM, offlineM, onlineM);
            }
        }
        else
        {
            cout << "Error calculated set does not match!" << endl;
#ifdef VERBOSE
            printIntersectionDiff();
#endif
        }
    }

    vector<biginteger> getIntersection()
    {
        return intersectionCalculated;
    }

    bool intersectionMatches()
    {
#ifdef VERBOSE
        cout << "Intersection calculated:" << endl;
        for (biginteger &interElem : intersectionCalculated)
        {
            cout << interElem << endl;
        }
        cout << "END" << endl;
#endif

        bool matches = false;
        if (intersectionCalculated.size() != 0 && dataIH.getIntersectionSet().size() != 0)
        {
            matches = is_permutation(dataIH.getIntersectionSet().begin(), dataIH.getIntersectionSet().end(),
                                     intersectionCalculated.begin());
        }
        else
        {
            matches = (intersectionCalculated.size() == dataIH.getIntersectionSet().size());
        }
        return matches;
    }

    void printIntersectionDiff()
    {
        auto expectedSet = dataIH.getIntersectionSet();
        auto calculatedSet = intersectionCalculated;
        sort(expectedSet.begin(), expectedSet.end());
        sort(calculatedSet.begin(), calculatedSet.end());

        vector<biginteger> difference;
        set_difference(expectedSet.begin(), expectedSet.end(),
                       calculatedSet.begin(), calculatedSet.end(),
                       difference.begin());
        cout << "Difference:" << endl;
        for (auto &value : difference)
        {
            cout << value << endl;
        }
    }

    void exportMeasurements(PSIMeasurement &setUpM, PSIMeasurement &offlineM, PSIMeasurement &onlineM)
    {
        long phaseEndingSignalSize = 4;
        ofstream outputFile(exportFileName, std::ios_base::app);
        if (outputFile.is_open())
        {
            outputFile << "SetupTime," << setUpM.duration << endl;
            outputFile << "SetupBytesIn," << setUpM.bytesIn - phaseEndingSignalSize << endl;
            outputFile << "SetupBytesOut," << setUpM.bytesOut << endl;
            outputFile << "OfflineTime," << offlineM.duration << endl;
            outputFile << "OfflineBytesIn," << offlineM.bytesIn - phaseEndingSignalSize << endl;
            outputFile << "OfflineBytesOut," << offlineM.bytesOut << endl;
            outputFile << "OnlineTime," << onlineM.duration << endl;
            outputFile << "OnlineBytesIn," << onlineM.bytesIn << endl;
            outputFile << "OnlineBytesOut," << onlineM.bytesOut << endl;
        }
        else
        {
            throw runtime_error("Error, could not write measurements");
        }
        outputFile.close();
    }
};