#pragma once
#include "infra/Common.hpp" //for correct uint64_t definitions, etc.

/**
 * @brief Helper struct to combine measurements for each phase.
 *
 */
struct PSIMeasurement
{

    int64_t duration;
    long bytesIn;
    long bytesOut;

    PSIMeasurement(int64_t duration, long bytesIn, long bytesOut)
        : duration(duration), bytesIn(bytesIn), bytesOut(bytesOut)
    {
    }
};