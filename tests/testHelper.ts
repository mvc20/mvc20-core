
import { mvc, buildTypeClasses } from 'mvc-scrypt'
import Common = require('../deployments/common')
import { inputSatoshis, dummyTxId } from '../scrypt_helper'

import { privateKey } from '../privateKey'

//const TxUtil = Common.genContract('txUtil', false, false)
const jsonDescr = Common.loadDescription('./fixture/autoGen/token_desc.json');
export const { TxInputProof, TxOutputProof } = buildTypeClasses(jsonDescr);
const addInput = Common.addInput
const address1 = privateKey.toAddress()

export function getTxOutputProofScrypt(tx: mvc.Transaction, outputIndex: number, emptyScriptHash: boolean = false) {
    const res = new TxOutputProof(Common.getTxOutputProof(tx, outputIndex, emptyScriptHash))
    return res
}

export function getEmptyTxOutputProofScrypt() {
    return new TxOutputProof(Common.getEmptyTxOutputProof())
}

export function createInputTx(contract, prevTx: mvc.Transaction | undefined, outputSatoshis: number = inputSatoshis) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    if (prevTx) {
        addInput(tx, prevTx.id, 0, prevTx.outputs[0].script, inputSatoshis, [])
    } else {
        addInput(tx, dummyTxId, 0, mvc.Script.buildPublicKeyHashOut(address1), inputSatoshis, [], true)
    }
    tx.addOutput(new mvc.Transaction.Output({
        script: contract.lockingScript,
        satoshis: outputSatoshis,
    }))
    return tx
}
