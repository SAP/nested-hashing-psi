cmake_minimum_required(VERSION 3.0.0)
project(BS-PSI VERSION 0.1.0)
set(CMAKE_CXX_STANDARD 11)
#[[
include(CTest)
enable_testing()]]



FIND_PACKAGE(OpenFHE REQUIRED)
#eval
set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )

#debug
#set( CMAKE_CXX_FLAGS "-DOPENFHE_VERSION=0.9.2 -DMATHBACKEND=4")

message("Flags:" ${CMAKE_CXX_FLAGS})

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
### add directories for other OpenFHE modules as needed for your project

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES})


#[[
find_library(TCMALLOC_LINK libtcmalloc_minimal.a PATH ${OpenFHE_INCLUDE}/third-party/lib)
message("tcmalloc Lib: " ${TCMALLOC_LINK})
link_libraries(${TCMALLOC_LINK})
]]

#set(BUILD_STATIC_OFHE ON)
message("Build static FHE: " ${BUILD_STATIC_OFHE})
if(BUILD_STATIC_OFHE)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
    message("Static OpenFHE linked")
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
    message("Dynamic OpenFHE linked")
endif()


#[[
find_package(OpenMP REQUIRED)
if(${OpenMP_CXX_FOUND}) 
message("Compile with OpenMP")
link_libraries(OpenMP::OpenMP_CXX )
else()
message("OpenMP_CXX not found")
endif()
]]

set(LIBSCAPI_DIR ${CMAKE_SOURCE_DIR}/../libscapi/)
message("LibscapiDIR: " ${LIBSCAPI_DIR})

find_library(LIB_TO_INCLUDE libscapi.a PATH ${LIBSCAPI_DIR})
include_directories(${LIBSCAPI_DIR}/include)

#message(${LIB_TO_INCLUDE})

#[[
find_package(libOTe REQUIRED)
link_libraries(oc::libOTe)
]]

link_libraries(${LIB_TO_INCLUDE})

#set(Boost_USE_STATIC_LIBS   ON)
set(Boost_USE_MULTITHREADED ON)
FIND_PACKAGE(Boost 1.71.0 EXACT COMPONENTS thread system program_options REQUIRED)
if(${Boost_FOUND}) 
message("Compile with Boost")
INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS})
link_libraries(${Boost_LIBRARIES})
else()
message("Boost not found")
endif()



#[[
add_compile_options(-lboost_program_options)
add_compile_options(-lboost_system)
add_compile_options(-L~/boost_1_71_0/stage/lib)
]]

link_libraries(ssl crypto gmp pthread)

include_directories(${CMAKE_SOURCE_DIR})
add_subdirectory(src)
link_libraries(PSILib)

add_subdirectory(tests)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

