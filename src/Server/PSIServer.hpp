/**
 * @file PSIServer.hpp
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

class PSIServer
{

protected:
    PSIParameter &serverParams;
    std::vector<biginteger> &serverSet;
    shared_ptr<CommParty> channel;
    boost::asio::io_service io_service;
    // boost::thread t;
    string exportFileName;
    string protocolName;
    int64_t offlineComputation;
    int64_t onlineComputation;

    void connectToClient()
    {
        // t = boost::thread(boost::bind(&boost::asio::io_service::run, &io_service));
        auto me = SocketPartyData(boost_ip::address::from_string(serverParams.ip), serverParams.port + 1);
        auto other = SocketPartyData(boost_ip::address::from_string(serverParams.ip), serverParams.port);
        channel = make_shared<CommPartyTCPSynced>(io_service, me, other, 0);
        channel->join(500, 5000000);
    }

    void closeConnection()
    {
        io_service.stop();
        // t.join();
    }

    void signalPhaseOver()
    {
        channel->writeWithSize("");
    }

public:
    PSIServer(DataInputHandler &dataIH, PSIParameter &serverParams, string protocolName)
        : serverParams(serverParams), serverSet(dataIH.getServerSet()), protocolName(protocolName)
    {

        exportFileName = "MServer_CS_" + std::to_string(serverParams.clientSetSize) + "_SS_" + std::to_string(serverParams.serverSetSize) + "_P_" + protocolName + "_T_" + std::to_string(serverParams.numberOfThreads);

        std::time_t tTime = std::time(nullptr);
        char timeStr[80];
        std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d", std::localtime(&tTime));
        exportFileName += "_" + string(timeStr);
    }
    virtual void runSetUpPhase() = 0;
    virtual void runOfflinePhase() = 0;
    virtual void runOnlinePhase() = 0;
    void run()
    {
#ifdef VERBOSE
        cout << "Run " << protocolName << endl;
#endif
        connectToClient();
#ifdef VERBOSE
        cout << "Run Setup" << endl;
#endif
        runSetUpPhase();
        signalPhaseOver();
#ifdef VERBOSE
        cout << "Run Offline" << endl;
#endif
        runOfflinePhase();
        signalPhaseOver();
#ifdef VERBOSE
        cout << "Run Online" << endl;
#endif
        runOnlinePhase();
        closeConnection();
    }

    void exportMeasurements()
    {
        // Currently not used, because cant separate computation from communication
        ofstream outputFile(exportFileName, std::ios_base::app);
        if (outputFile.is_open())
        {
            outputFile << "OfflineComputationTime," << offlineComputation << endl;
            outputFile << "OnlineComputationTime," << onlineComputation << endl;
        }
        else
        {
            cout << "Error, could not write measurements" << endl;
        }
        outputFile.close();
    }
};