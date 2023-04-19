add_executable(TestClient TestClientDJ.cpp)
add_executable(TestClientECC TestClientECC.cpp)

add_executable(TestServer TestServerDJ.cpp)
add_executable(TestServerECC TestServerECC.cpp )
add_executable(TestServerSimECC TestServerSimECC.cpp)

#[[
add_executable(TestOT TestOT.cpp)
]]
add_executable(TestDamgardJurik TestDamgardJurik.cpp)
add_executable(TestElGamal TestElGamal.cpp)
add_executable(TestElGamalPIE TestElGamalPIE.cpp)
add_executable(TestDataInput TestDataInput.cpp)
add_executable(NestedCuckooEval HashingEvaluation.cpp)
add_executable(CuckooEval CuckooHashingEvaluation.cpp)
add_executable(TestOpenFHE TestOpenFHE.cpp)
add_executable(TestFHEInnerP TestFHEInnerP.cpp)
add_executable(TestFHEPIE TestFHEPIE.cpp)
add_executable(TestBatchedFHEPIE TestBatchedFHEPIE.cpp)