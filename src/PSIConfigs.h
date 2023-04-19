/**
 * @file PSIConfigs.h
 * @brief File to define common (global) stuff
 * @version 0.1
 *
 */
#pragma once
#include "cryptoInfra/PlainText.hpp" //needed for bitinteger definition
//#define VERBOSE //should be disabled for performance measurements
typedef vector<vector<shared_ptr<AsymmetricCiphertext>>> indexVectorType;
#define OpenSSLCurveDir "/home/testuser/libscapi/include/configFiles/NISTEC.txt" // need to be adjusted