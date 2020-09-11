// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include <primitives/transaction.h>
#include <script/script_error.h>
#include <script/script_flags.h>
#include <script/script_metrics.h>
#include <script/sighashtype.h>

#include <cstdint>
#include <vector>

class CPubKey;
class CScript;
class CTransaction;
class uint256;

enum class SigVersion
{
    BASE = 0,        //!< Bare scripts and BIP16 P2SH-wrapped redeemscripts
    TAPROOT = 2,     //!< Taproot with 32-byte program, not BIP16 P2SH-wrapped, key path spending; see BIP 341
    TAPSCRIPT = 3,   //!< Taproot with 32-byte program, not BIP16 P2SH-wrapped, script path spending, leaf version 0xc0; see BIP 342
};

struct ScriptExecutionData {};

/** Signature hash sizes */
static constexpr size_t TAPROOT_KEY_SIZE = 33;

static constexpr uint8_t TAPROOT_LEAF_MASK = 0xfe;
static constexpr size_t TAPROOT_CONTROL_BASE_SIZE = 33;
static constexpr size_t TAPROOT_CONTROL_NODE_SIZE = 32;
static constexpr size_t TAPROOT_CONTROL_MAX_NODE_COUNT = 128;
static constexpr size_t TAPROOT_CONTROL_MAX_SIZE = TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;

template <class T>
uint256 SignatureHash(const CScript &scriptCode, const T &txTo,
                      unsigned int nIn, SigHashType sigHashType,
                      const Amount amount,
                      const PrecomputedTransactionData *cache = nullptr,
                      uint32_t flags = SCRIPT_ENABLE_SIGHASH_FORKID);

class BaseSignatureChecker {
public:
    virtual bool VerifySignature(const std::vector<uint8_t> &vchSig,
                                 const CPubKey &vchPubKey,
                                 const uint256 &sighash) const;

    virtual bool CheckSig(const std::vector<uint8_t> &vchSigIn,
                          const std::vector<uint8_t> &vchPubKey,
                          const CScript &scriptCode, uint32_t flags) const {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum &nLockTime) const {
        return false;
    }

    virtual bool CheckSequence(const CScriptNum &nSequence) const {
        return false;
    }

    virtual bool CheckSigTaproot(const std::vector<uint8_t> &vchSigIn,
                                 const std::vector<uint8_t> &vchPubKey,
                                 SigVersion sigversion) const {
        return false;
    }

    virtual ~BaseSignatureChecker() {}
};

template <class T>
class GenericTransactionSignatureChecker : public BaseSignatureChecker {
private:
    const T *txTo;
    unsigned int nIn;
    const Amount amount;
    const PrecomputedTransactionData *txdata;

public:
    GenericTransactionSignatureChecker(const T *txToIn, unsigned int nInIn,
                                       const Amount &amountIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(nullptr) {}
    GenericTransactionSignatureChecker(
        const T *txToIn, unsigned int nInIn, const Amount &amountIn,
        const PrecomputedTransactionData &txdataIn)
        : txTo(txToIn), nIn(nInIn), amount(amountIn), txdata(&txdataIn) {}

    // The overridden functions are now final.
    bool CheckSig(const std::vector<uint8_t> &vchSigIn,
                  const std::vector<uint8_t> &vchPubKey,
                  const CScript &scriptCode,
                  uint32_t flags) const final override;
    bool CheckSigTaproot(const std::vector<uint8_t> &vchSigIn,
                         const std::vector<uint8_t> &vchPubKey,
                         SigVersion sigversion) const override;
    bool CheckLockTime(const CScriptNum &nLockTime) const final override;
    bool CheckSequence(const CScriptNum &nSequence) const final override;
};

using TransactionSignatureChecker =
    GenericTransactionSignatureChecker<CTransaction>;
using MutableTransactionSignatureChecker =
    GenericTransactionSignatureChecker<CMutableTransaction>;

bool EvalScript(std::vector<std::vector<uint8_t>> &stack, const CScript &script,
                uint32_t flags, const BaseSignatureChecker &checker,
                SigVersion sigversion, ScriptExecutionData& execdata,
                ScriptExecutionMetrics &metrics, ScriptError *error = nullptr);
static inline bool EvalScript(std::vector<std::vector<uint8_t>> &stack,
                              const CScript &script,
                              uint32_t flags, const BaseSignatureChecker &checker,
                              ScriptExecutionMetrics &metrics, ScriptError *serror = nullptr) {
    ScriptExecutionData execdata;
    return EvalScript(stack, script, flags, checker, SigVersion::BASE, execdata, metrics, serror);
}
static inline bool EvalScript(std::vector<std::vector<uint8_t>> &stack,
                              const CScript &script, uint32_t flags,
                              const BaseSignatureChecker &checker,
                              ScriptError *error = nullptr) {
    ScriptExecutionMetrics dummymetrics;
    return EvalScript(stack, script, flags, checker, dummymetrics, error);
}

/**
 * Execute an unlocking and locking script together.
 *
 * Upon success, metrics will hold the accumulated script metrics.
 * (upon failure, the results should not be relied on)
 */
bool VerifyScript(const CScript &scriptSig, const CScript &scriptPubKey,
                  uint32_t flags, const BaseSignatureChecker &checker,
                  ScriptExecutionMetrics &metricsOut,
                  ScriptError *serror = nullptr);
static inline bool VerifyScript(const CScript &scriptSig,
                                const CScript &scriptPubKey, uint32_t flags,
                                const BaseSignatureChecker &checker,
                                ScriptError *serror = nullptr) {
    ScriptExecutionMetrics dummymetrics;
    return VerifyScript(scriptSig, scriptPubKey, flags, checker, dummymetrics,
                        serror);
}

int FindAndDelete(CScript &script, const CScript &b);

#endif // BITCOIN_SCRIPT_INTERPRETER_H
