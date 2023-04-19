/**
 * @file DataInputHandler.hpp
 * 
 * @version 0.1
 */

#pragma once
#include "src/PSIConfigs.h"
#include <vector>
#include "cryptoInfra/PlainText.hpp"

/**
 * @brief Abstract class for PSI data input. Provides references to the (generated/readed) input sets
 * (and precalculated intersections for testing)
 *
 */
class DataInputHandler
{

public:
    virtual vector<biginteger> &getClientSet() = 0;
    virtual vector<biginteger> &getServerSet() = 0;
    virtual vector<biginteger> &getIntersectionSet() = 0;
};
