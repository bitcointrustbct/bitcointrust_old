// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"


static const int nCheckpointSpan = 500;

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (     0, uint256("0x00000bee18888d3bfe358f523fff7891c8adc5ca85fe371f9b7115253589659c"))
        (     1, uint256("0x0000058c1e64c0c185d1da2491ccfab4f4441150b9bb07e70e654319a1007ef4"))
        (    10, uint256("0x000008c6fdd14d281f8f58b3a9541ecdd5059f0026f498ab3a4cd486938dd44c"))
        (   100, uint256("0x000001476cc7cc9351fce6930a2e2838f6db7b2cb3830f765ca2859364255cf7"))
        (   200, uint256("0x000006c13852cd543e7cff7f783b4b595395b97864ec394e5e8bfb67e1f5b5fc"))
        (   300, uint256("0x000003dabc37d133fc16ca93066dafb99a13f3c07fbf489940aa67568df870e2"))
        (   400, uint256("0x0000023a02cbb206a84e4ecda3e5bcd01918e75a6d6fa975207e16700086664c"))
        (   500, uint256("0x000003c0a9b49fc39605490814bf5b9deb1ad197b5ef7951141df6f3817cd5ba"))
        (   600, uint256("0x000001841ea69ae2ba63c3f2166fb1bde57c7d3d379e03d6acbe3ec8eed0fc5a"))
        (   700, uint256("0x0000049c7ee8103ba5bca173a58635174ab3198cc6a79462850868eaaa5c6b37"))
        (   800, uint256("0x000001c9bb1678727668f3a08abd61ca8c8c58c428529e0938a78e533f3f724d"))
        (  1000, uint256("0x000001803bcf27c7560ec83a2b75bfb73f75f7be229e319ea70fff5b61e00f5a"))
        ( 10000, uint256("0x000006539f068032d77a33815b71a41478a38e8267dc83f2be37eee1eb9a7dfd"))
        ( 20000, uint256("0x00000b860d9309f89776ff9fbbd3dbdff6a2139941f01f7a939bc49e9547fbe3"))
        ( 30000, uint256("0x000005beb3d4bc818b989659514384a51a8dc9cc194f830c66e41488b43fdf54"))
        ( 40000, uint256("0x000002d65cfccdc1ffcb107d328f051a0fe6bdb2469c661663e92b1faabdd3ab"))
        ( 50000, uint256("0x0000006160264e97deb52eca8a23607953d1d741f42d140f5ace78cef89a75ec"))
        (100000, uint256("0x000001e4e50d3b505ac6d8cc153718dc6f261927d60c1220b240698c46db8223"))
        (200000, uint256("0x000001c1c85d84bb7eab090509aba64a1810a0e4e486ba60211018fc3e3518ae"))
        (300000, uint256("0x00000293c332cb0dc7de31770c2b3928ea4f98cf1af952f09893529a2d5422f6"))
        (350000, uint256("0x000000fd4f158e61ee85af3a864122a29bfd3d4cbd55569a0baac6fdeecf4a4d"))
    ;

    // TestNet has no checkpoints
    static MapCheckpoints mapCheckpointsTestnet;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        if (checkpoints.empty())
            return 0;
        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    // Automatically select a suitable sync-checkpoint 
    const CBlockIndex* AutoSelectSyncCheckpoint()
    {
        const CBlockIndex *pindex = pindexBest;
        // Search backward for a block within max span and maturity window
        while (pindex->pprev && pindex->nHeight + nCheckpointSpan > pindexBest->nHeight)
            pindex = pindex->pprev;
        return pindex;
    }

    // Check against synchronized checkpoint
    bool CheckSync(int nHeight)
    {
        const CBlockIndex* pindexSync = AutoSelectSyncCheckpoint();

        if (nHeight <= pindexSync->nHeight)
            return false;
        return true;
    }
}
