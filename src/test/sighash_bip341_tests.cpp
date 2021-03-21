// Copyright (c) 2012-2019 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <core_io.h>
#include <hash.h>
#include <policy/policy.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/standard.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

typedef std::vector<uint8_t> valtype;
typedef std::vector<valtype> stacktype;

BOOST_FIXTURE_TEST_SUITE(sighash_bip341_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(prepare_spent_outputs) {
    LOCK(cs_main);
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);

    CMutableTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_1));
    txFrom.vout[0].nValue = 1000 * SATOSHI;

    AddCoins(coins, CTransaction(txFrom), 0);

    CMutableTransaction txTo;
    txTo.vin.resize(1);
    txTo.vin[0].prevout = COutPoint(txFrom.GetId(), 0);
    txTo.vout.resize(1);
    txTo.vout[0].scriptPubKey =
        GetScriptForDestination(ScriptHash(CScript() << OP_2));
    txTo.vout[0].nValue = 3000 * SATOSHI;

    PrecomputedTransactionData txdata =
        PrecomputedTransactionData::FromCoinsView(txTo, coins);
    BOOST_CHECK(txdata.m_spent_outputs == txFrom.vout);
}

static const std::vector<uint32_t> allflags{
    SCRIPT_VERIFY_NONE,
    STANDARD_SCRIPT_VERIFY_FLAGS,
};

void CheckCodesepPos(const CScript &script,
                     const uint32_t expected_codesep_pos) {
    for (uint32_t flags : allflags) {
        BaseSignatureChecker sigchecker;
        ScriptExecutionMetrics metrics = {};
        ScriptExecutionData execdata = {};
        stacktype stack = {};
        bool r =
            EvalScript(stack, script, flags, sigchecker, metrics, execdata);
        BOOST_CHECK(r);
        BOOST_CHECK_EQUAL(execdata.m_codeseparator_pos, expected_codesep_pos);
        BOOST_CHECK_MESSAGE(execdata.m_codeseparator_pos ==
                                expected_codesep_pos,
                            "For script '" << ScriptToAsmStr(script) << "'");
    }
}

BOOST_AUTO_TEST_CASE(script_execution_data) {
    valtype data10(10);
    valtype data520(520);
    // Test unconditional cases
    CheckCodesepPos(CScript() << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << data10 << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << data520 << OP_1, 0xffff'ffff);
    CheckCodesepPos(CScript() << OP_CODESEPARATOR << data10 << OP_1, 0);
    CheckCodesepPos(CScript() << OP_CODESEPARATOR << data520 << OP_1, 0);
    CheckCodesepPos(CScript() << data520 << OP_CODESEPARATOR << OP_1, 1);
    CheckCodesepPos(CScript() << data10 << OP_CODESEPARATOR << OP_1, 1);
    CheckCodesepPos(CScript() << data520 << OP_1 << OP_CODESEPARATOR, 2);
    CheckCodesepPos(CScript() << data520 << data10 << OP_1 << OP_CODESEPARATOR,
                    3);
    CheckCodesepPos(CScript() << data520 << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                              << OP_NOP << OP_CODESEPARATOR,
                    6);

    // Test conditional cases
    CheckCodesepPos(CScript() << 0 << OP_IF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript() << 1 << OP_IF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    3);
    CheckCodesepPos(CScript() << 0 << OP_NOTIF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    3);
    CheckCodesepPos(CScript() << 1 << OP_NOTIF << OP_NOP << OP_CODESEPARATOR
                              << OP_NOP << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript()
                        << 1 << 1 << 1 << OP_IF << OP_IF << OP_IF
                        << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF << OP_ENDIF,
                    6);
    CheckCodesepPos(CScript()
                        << 1 << 0 << 1 << OP_IF << OP_IF << OP_IF
                        << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF << OP_ENDIF,
                    0xffff'ffff);
    CheckCodesepPos(CScript() << 1 << 0 << 1 << OP_IF << OP_IF << OP_IF
                              << OP_CODESEPARATOR << OP_ENDIF << OP_ELSE
                              << OP_CODESEPARATOR << OP_ENDIF << OP_ENDIF,
                    9);
    CheckCodesepPos(CScript() << 1 << 0 << 1 << OP_IF << OP_CODESEPARATOR
                              << OP_IF << OP_IF << OP_CODESEPARATOR << OP_ENDIF
                              << OP_ELSE << OP_CODESEPARATOR << OP_ENDIF
                              << OP_ELSE << OP_CODESEPARATOR << OP_ENDIF,
                    10);
}

BOOST_AUTO_TEST_SUITE_END()
