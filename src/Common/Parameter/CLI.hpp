#pragma once
#include "PSIParameter.hpp"
#include "HashTableParameter.hpp"

pair<bool, pair<PSIParameter, HashTableParameter>> readParameters(int argc, char *argv[]);