/**
 * @file ElGamalPIE.hpp
 * 
 * @version 0.1
 *
 *
 */
#pragma once
#include "ElGamalPIE.hpp"
#include "PrecompElGamalPIE.hpp"
#include "FHEHIPPIE.hpp"

struct ElGamalPIECollection
{

    AddHomElGamalEnc cryptor;
    vector<ElGamalPIE> myPIEs;

    ElGamalPIECollection(AddHomElGamalEnc &&cryptor)
        : cryptor(cryptor),
          myPIEs(vector<ElGamalPIE>())
    {
    }

    void runAll()
    {
        for (auto &pie : myPIEs)
        {
            pie.run();
        }
    }

    void addPIE(CuckooHashTable &ct)
    {
        myPIEs.push_back(ElGamalPIE(cryptor, ct));
    }
};

struct PrecompElGamalPIECollection
{

    AddHomElGamalEnc cryptor;
    vector<PrecompElGamalPIE> myPIEs;

    PrecompElGamalPIECollection(AddHomElGamalEnc &&cryptor)
        : cryptor(cryptor),
          myPIEs(vector<PrecompElGamalPIE>())
    {
    }

    void runAll()
    {
        for (auto &pie : myPIEs)
        {
            pie.run();
        }
    }

    void precompAll()
    {
        for (auto &pie : myPIEs)
        {
            pie.precomp();
        }
    }

    void addPIE(CuckooHashTable &ct, vector<vector<AsymmetricCiphertext *>> &&randomIndexMatrix)
    {
        PrecompElGamalPIE mpie(cryptor, ct);
        mpie.setIndex(std::move(randomIndexMatrix));
        myPIEs.push_back(std::move(mpie));
    }
};

struct FHEHIPPIECollection
{
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptor;
    lbcrypto::PublicKey<FHEEncType> &pK;
    vector<FHEHIPPIE> myPIEs;

    FHEHIPPIECollection(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptor, lbcrypto::PublicKey<FHEEncType> &pK)
        : cryptor(cryptor), pK(pK),
          myPIEs(vector<FHEHIPPIE>())
    {
    }

    void runAll()
    {
        for (auto &pie : myPIEs)
        {
            pie.run();
        }
    }

    void addPIE(CuckooHashTable &ct)
    {
        myPIEs.push_back(FHEHIPPIE(cryptor, pK, ct));
    }
};