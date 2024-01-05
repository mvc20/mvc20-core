import { expect } from 'chai';
import { mvc, Bytes, getPreimage, toHex, Ripemd160, SigHashPreimage, PubKey, Sig, signTx, buildTypeClasses } from 'mvc-scrypt'
import Mvc20Proto  = require('../deployments/mvc20Proto')
import { dummyTxId } from '../scrypt_helper'

import { privateKey, privateKey2, privateKey3 } from '../privateKey';

import Proto = require('../deployments/protoheader')
import TokenProto = require('../deployments/tokenProto')
import Common = require('../deployments/common')
import UniqueProto = require('../deployments/uniqueProto')
import { createInputTx, getTxOutputProofScrypt, getEmptyTxOutputProofScrypt } from './testHelper';
import { inputSatoshis } from '../scrypt_helper'

const tokenType = Common.getUInt32Buf(TokenProto.PROTO_TYPE)
const tokenVersion = Common.getUInt32Buf(TokenProto.PROTO_VERSION)

const uniqueType = Common.getUInt32Buf(UniqueProto.PROTO_TYPE)
const uniqueVersion = Common.getUInt32Buf(UniqueProto.PROTO_VERSION)

const mvc20TokenName = Buffer.alloc(40, 0)
mvc20TokenName.write('test reward token')
const mvc20TokenSymbol = Buffer.alloc(20, 0)
mvc20TokenSymbol.write('trt')

const decimalNum = Common.getUInt8Buf(8)

const address1 = privateKey.toAddress()
const address2 = privateKey2.toAddress()
const burnAddress = mvc.Address.fromPublicKeyHash(Buffer.alloc(20, 0))
const sigtype = mvc.crypto.Signature.SIGHASH_ALL | mvc.crypto.Signature.SIGHASH_FORKID

const genContract = Common.genContract
const addInput = Common.addInput
const addOutput = Common.addOutput
const USE_DESC = false
const USE_RELEASE = false
const burnSats = 100000

const Mvc20Main = genContract('mvc20/mvc20Main', USE_DESC, USE_RELEASE)
const Mvc20Genesis = genContract('mvc20/mvc20TokenGenesis', USE_DESC, USE_RELEASE)
const Mvc20Mint = genContract('mvc20/mvc20Mint', USE_DESC, USE_RELEASE)
const Token = genContract('token/token', true, false)

const jsonDescr = Common.loadDescription('../out/token_debug_desc.json');
export const { TxInputProof, TxOutputProof, BlockRabinData } = buildTypeClasses(jsonDescr);

let mvc20SensibleID, mvc20TokenSensibleID, tokenCodeHash 
let mvc20TokenID, mvc20ID

let transferCheckCodeHashArray, unlockContractCodeHashArray, genesisHash, mvc20GenesisHash
let mvc20MainCodeHash, mvc20MintCodeHash 

let contractHashRoot, contractHashArray

function getCodeHash(scriptCodeBuf: Buffer) {
    return mvc.crypto.Hash.sha256ripemd160(Buffer.concat([scriptCodeBuf, Buffer.from('6a', 'hex')])) 
}

function initContractHash() {

    mvc20TokenSensibleID = Buffer.concat([
        Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse()),
        Common.getUInt32Buf(22),
    ]).toString('hex')
    mvc20SensibleID = Buffer.concat([
        Buffer.from([...Buffer.from(dummyTxId, 'hex')].reverse()),
        Buffer.alloc(4, 0),
    ]).toString('hex')

    const transferCheckCodeHash = new Bytes(Buffer.alloc(20, 0).toString('hex'))
    transferCheckCodeHashArray = [transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash, transferCheckCodeHash]
    unlockContractCodeHashArray = transferCheckCodeHashArray
    genesisHash = Buffer.alloc(20, 0).toString('hex')

    mvc20ID = mvc.crypto.Hash.sha256ripemd160(Buffer.concat([
        Buffer.from(mvc20SensibleID, 'hex')
    ])).toString('hex')

    const tokenContract = new Token(transferCheckCodeHashArray, unlockContractCodeHashArray)
    tokenCodeHash = getCodeHash(tokenContract.lockingScript.toBuffer()).toString('hex')

    // mvc20 main
    const mvc20Main = new Mvc20Main()
    const code = mvc20Main.lockingScript.toBuffer()
    mvc20MainCodeHash = getCodeHash(code).toString('hex')

    // mvc20TokenGenesis
    const mvc20TokenGenesis = createGenesisContract()
    const mvc20GenesisHashBuf = mvc.crypto.Hash.sha256ripemd160(mvc20TokenGenesis.lockingScript.toBuffer())
    mvc20GenesisHash = mvc20GenesisHashBuf.toString('hex')
    mvc20TokenID = mvc.crypto.Hash.sha256ripemd160(Buffer.concat([
        mvc20GenesisHashBuf,
        Buffer.from(mvc20TokenSensibleID, 'hex')
    ])).toString('hex')

    const mvc20Mint = new Mvc20Mint(new Bytes(mvc20ID), new Bytes(mvc20MainCodeHash), new Bytes(tokenCodeHash), new Bytes(mvc20GenesisHash), burnSats)
    mvc20MintCodeHash = getCodeHash(mvc20Mint.lockingScript.toBuffer()).toString('hex')

    // create merkle tree
    contractHashArray = Buffer.concat([
        Buffer.from(mvc20MintCodeHash, 'hex'),
    ])
    contractHashRoot = mvc.crypto.Hash.sha256ripemd160(contractHashArray)

}

function createMvc20Main(info: Mvc20Proto.Mvc20Info) {
    const mvc20Main = new Mvc20Main()
    const data = Common.buildScriptData(Buffer.concat([
        Common.getUInt64Buf(info.maxTokenAmount),
        Common.getUInt64Buf(info.maxMintAmount),
        Common.getUInt64Buf(info.mintedAmount),
        contractHashRoot,
        Common.getUInt32Buf(Mvc20Proto.CUSTOM_DATA_LEN),
        Buffer.from(mvc20SensibleID, 'hex'),
        uniqueVersion,
        uniqueType,
        Proto.PROTO_FLAG,
    ]))
    mvc20Main.setDataPart(data.toString('hex'))
    return mvc20Main
}

export  function unlockMvc20Main(
    tx: mvc.Transaction,
    prevouts: Buffer,
    mvc20Main,
    inputIndex: number,
    contractTx: mvc.Transaction,
    mvc20Tx: mvc.Transaction,
    prevMvc20TxInputIndex: number,
    prevMvc20Tx: mvc.Transaction,
    op: number,
    contractHashArray: Buffer,
    mvc20SensibleID: string,
    expected: boolean = true) {

    // mvc20Main unlock
    const mvc20OutputIndex = tx.inputs[inputIndex].outputIndex
    const inputSatoshis = mvc20Tx.outputs[mvc20OutputIndex].satoshis
    const preimage = getPreimage(tx, mvc20Main.lockingScript.subScript(0), inputSatoshis, inputIndex, sigtype)
    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis
    }

    const contractTxOutputIndex = tx.inputs[0].outputIndex
    const contractTxScript = contractTx.outputs[contractTxOutputIndex].script.toBuffer()
    const contractTxProof = getTxOutputProofScrypt(contractTx, contractTxOutputIndex)

    const mvc20TxOutputProof = getTxOutputProofScrypt(mvc20Tx, mvc20OutputIndex)

    const mvc20TxInputProof = new TxInputProof(Common.getTxInputProof(mvc20Tx, prevMvc20TxInputIndex)[0])

    const prevMvc20OutputIndex = mvc20Tx.inputs[prevMvc20TxInputIndex].outputIndex
    const prevMvc20TxProof = getTxOutputProofScrypt(prevMvc20Tx, prevMvc20OutputIndex)

    let prevCustomData = new Bytes('')
    const sid = Common.genGenesisTxid(prevMvc20Tx.id, prevMvc20OutputIndex)
    if (sid !== mvc20SensibleID) {
        const prevMvc20ScriptBuf = prevMvc20Tx.outputs[prevMvc20OutputIndex].script.toBuffer()
        prevCustomData = new Bytes(UniqueProto.getCustomData(prevMvc20ScriptBuf).toString('hex'))
    }

    const result = mvc20Main.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // op contract hash proof
        contractTxProof,
        new Bytes(contractTxScript.toString('hex')),
        // main contract hash proof
        new Bytes(contractHashArray.toString('hex')),
        op,
        // mvc20 
        prevMvc20TxInputIndex,
        mvc20TxOutputProof.txHeader,
        mvc20TxInputProof,
        prevMvc20TxProof,
        prevCustomData
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createGenesisContract(wrongMvc20TokenGenesisHash: boolean = false) {
    let dn = decimalNum.readUInt8()
    if (wrongMvc20TokenGenesisHash === true) {
        dn = dn + 1
    }
    const mvc20TokenGenesis = new Mvc20Genesis(new Bytes(mvc20MainCodeHash))
    const data = Common.buildScriptData(Buffer.concat([
        mvc20TokenName,
        mvc20TokenSymbol,
        Common.getUInt8Buf(dn),
        Buffer.alloc(20, 0), // address
        Buffer.alloc(8, 0), // token value
        Buffer.alloc(20, 0), // genesisHash
        Buffer.from(mvc20TokenSensibleID, 'hex'),
        tokenVersion,
        tokenType, // type
        Proto.PROTO_FLAG
    ]))
    mvc20TokenGenesis.setDataPart(data.toString('hex'))
    return mvc20TokenGenesis
}

function unlockMvc20Genesis(
    tx: mvc.Transaction,
    prevouts: Buffer,
    mvc20Genesis,
    inputIndex: number,
    // genesis
    prevGenesisTxInputIndex: number,
    genesisTx: mvc.Transaction,
    prevGenesisTx: mvc.Transaction,
    // mint
    mintTx: mvc.Transaction,
    // mvc20
    mvc20Tx: mvc.Transaction,
    contractHashArray: Buffer,
) {

    const sigtype = Common.SIG_HASH_SINGLE
    const outputIndex = tx.inputs[inputIndex].outputIndex
    const inputSatoshis = genesisTx.outputs[outputIndex].satoshis
    const preimage = getPreimage(tx, mvc20Genesis.lockingScript, inputSatoshis, inputIndex, sigtype)
    const txContext = {
        tx: tx,
        inputIndex: inputIndex,
        inputSatoshis: inputSatoshis
    }

    const [genesisTxInputProof, genesisTxHeader] = Common.getTxInputProof(genesisTx, prevGenesisTxInputIndex)

    const prevGenesisOutputIndex = genesisTx.inputs[prevGenesisTxInputIndex].outputIndex
    const prevGenesisTxProof = Common.getTxOutputProof(prevGenesisTx, prevGenesisOutputIndex)

    const mintOutputIndex = tx.inputs[0].outputIndex
    const mintScript = mintTx.outputs[mintOutputIndex].script.toBuffer()
    const mintTxProof = new TxOutputProof(Common.getTxOutputProof(mintTx, mintOutputIndex))

    const mvc20OutputIndex = tx.inputs[1].outputIndex
    const mvc20TxScript = mvc20Tx.outputs[mvc20OutputIndex].script.toBuffer()
    const mvc20TxProof = new TxOutputProof(Common.getTxOutputProof(mvc20Tx, mvc20OutputIndex))

    const mvc20GenesisOutputSatoshis = tx.outputs[2].satoshis

    const result = mvc20Genesis.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // genesis
        genesisTxHeader,
        // prev genesis input hash data
        prevGenesisTxInputIndex,
        new TxInputProof(genesisTxInputProof),
        // prev genesis tx output data
        prevGenesisTxProof.txHeader,
        prevGenesisTxProof.hashProof,
        prevGenesisTxProof.satoshiBytes,
        // addliq
        mintTxProof,
        new Bytes(mintScript.toString('hex')),
        // mvc20
        mvc20TxProof,
        new Bytes(mvc20TxScript.toString('hex')),
        // contract hash proof
        new Bytes(contractHashArray.toString('hex')),
        mvc20GenesisOutputSatoshis
    ).verify(txContext)
    expect(result.success, result.error).to.be.true
}

function createContractTx(lockingScript) {
    const tx = new mvc.Transaction()
    tx.version = Common.TX_VERSION
    tx.addInput(new mvc.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 0,
        script: ''
    }), mvc.Script.buildPublicKeyHashOut(address1), inputSatoshis)
    tx.addOutput(new mvc.Transaction.Output({
        script: lockingScript,
        satoshis: inputSatoshis
    }))
    return tx
}

function createMvc20MintContract(senderAddress: mvc.Address) {
    const mvc20Mint = new Mvc20Mint(new Bytes(mvc20ID), new Bytes(mvc20MainCodeHash), new Bytes(tokenCodeHash), new Bytes(mvc20GenesisHash), burnSats)
    const data = Common.buildScriptData(Buffer.concat([
        senderAddress.hashBuffer,
    ]))
    mvc20Mint.setDataPart(data.toString('hex'))
    const tx = createContractTx(mvc20Mint.lockingScript)
    return [mvc20Mint, tx]
}

function unlockMvc20Mint( 
    tx: mvc.Transaction,
    prevouts: Buffer,
    mintContract,
    // mvc20
    mvc20Tx: mvc.Transaction | undefined,
    // genesis
    genesisTx: mvc.Transaction | undefined,
    // token
    tokenScriptBuf: Buffer,
    // output
    changeSatoshis: number,
    changeAddress: mvc.Address,
    expected: boolean = true,
) {

    const tokenOutputSatoshis = 1

    const inputIndex = 0
    const input = tx.inputs[inputIndex]
    let output = <mvc.Transaction.Output>input.output
    const lockingScript = output.script.subScript(0)
    const inputSatoshis = output.satoshis
    let preimage = getPreimage(tx, lockingScript, inputSatoshis, inputIndex, sigtype)

    let mvc20TxProof = getEmptyTxOutputProofScrypt()
    let mvc20ScriptBuf = Buffer.alloc(0)
    let mvc20OutputSatoshis = 0
    let genesisTxProof = getEmptyTxOutputProofScrypt()
    let genesisScriptBuf = Buffer.alloc(0)
    let genesisOutputSatoshis = 0

    const mvc20OutputIndex = tx.inputs[1].outputIndex
    output = mvc20Tx.outputs[mvc20OutputIndex]
    mvc20ScriptBuf = output.script.toBuffer()
    mvc20OutputSatoshis = output.satoshis
    mvc20TxProof = getTxOutputProofScrypt(mvc20Tx, mvc20OutputIndex, true)

    const genesisOutputIndex = tx.inputs[2].outputIndex
    output = genesisTx.outputs[genesisOutputIndex]
    genesisScriptBuf = output.script.toBuffer()
    genesisOutputSatoshis = output.satoshis
    genesisTxProof = getTxOutputProofScrypt(genesisTx, genesisOutputIndex)

    const txContext = {
        tx,
        inputIndex,
        inputSatoshis,
    }
    let result = mintContract.unlock(
        new SigHashPreimage(toHex(preimage)),
        new Bytes(prevouts.toString('hex')),
        // mvc20
        new Bytes(mvc20ScriptBuf.toString('hex')),
        mvc20TxProof,
        // genesis
        new Bytes(genesisScriptBuf.toString('hex')),
        genesisTxProof,
        // token
        new Bytes(tokenScriptBuf.toString('hex')),
        // output
        mvc20OutputSatoshis, 
        tokenOutputSatoshis,
        genesisOutputSatoshis,
        new Ripemd160(changeAddress.hashBuffer.toString('hex')),
        changeSatoshis,
    ).verify(txContext)
    if (expected === false) {
        expect(result.success, result.error).to.be.false
    } else {
        expect(result.success, result.error).to.be.true
    }
}

function createTokenContract(addressBuf: Buffer, amount: bigint) {
    const token = new Token(transferCheckCodeHashArray, unlockContractCodeHashArray)
    const name = mvc20TokenName
    const symbol = mvc20TokenSymbol
    const sensibleID = mvc20TokenSensibleID
    const tokenGenesisHash = mvc20GenesisHash
    const data = Common.buildScriptData(Buffer.concat([
        name,
        symbol,
        decimalNum,
        addressBuf,
        Common.getUInt64Buf(amount),
        Buffer.from(tokenGenesisHash, 'hex'),
        Buffer.from(sensibleID, 'hex'),
        Common.getUInt32Buf(TokenProto.PROTO_VERSION),
        Common.getUInt32Buf(TokenProto.PROTO_TYPE), // type
        Proto.PROTO_FLAG
    ]))
    token.setDataPart(data.toString('hex'))
    return token
}

function mint(info: Mvc20Proto.Mvc20Info, options: any = {}) {

    const tx = mvc.Transaction()
    tx.version = Common.TX_VERSION

    let prevouts = []
    const senderAddress = address1
    // input
    // mvc20Mint
    const [mintContract, mintTx] = createMvc20MintContract(senderAddress)
    addInput(tx, mintTx.id, 0, mintContract.lockingScript, mintTx.outputs[0].satoshis, prevouts)

    // mvc20Main
    let mvc20Main = createMvc20Main(info)
    if (options.mvc20Main) {
        mvc20Main = options.mvc20Main
    }
    const prevMvc20Tx = createInputTx(mvc20Main, undefined)
    const mvc20Tx = createInputTx(mvc20Main, prevMvc20Tx)
    addInput(tx, mvc20Tx.id, 0, mvc20Main.lockingScript, inputSatoshis, prevouts)

    // genesis
    const mvc20TokenGenesis = createGenesisContract(options.wrongMvc20TokenGenesis)
    const prevMvc20GenesisTx = createInputTx(mvc20TokenGenesis, undefined)
    const mvc20GenesisTx = createInputTx(mvc20TokenGenesis, prevMvc20GenesisTx)
    addInput(tx, mvc20GenesisTx.id, 0, mvc20TokenGenesis.lockingScript, inputSatoshis, prevouts)

    // mvc (optional)

    const prevoutsBuf = Buffer.concat(prevouts)

    const newMintedAmount = info.mintedAmount + BigInt(1)
    const newTokenAmount = info.maxTokenAmount / info.maxMintAmount

    // mvc20Main
    let scriptBuf = Mvc20Proto.getNewScript(mvc20Main.lockingScript.toBuffer(), newMintedAmount)
    addOutput(tx, mvc.Script.fromBuffer(scriptBuf), inputSatoshis)

    // mvc20 token
    let tokenMintedAmount = newTokenAmount
    if (options.mvc20TokenAmountExtra) {
        tokenMintedAmount += BigInt(options.mvc20TokenAmountExtra)
    }
    let mvc20TokenLockingScript = createTokenContract(senderAddress.hashBuffer, tokenMintedAmount).lockingScript
    const tokenScriptBuf = mvc20TokenLockingScript.toBuffer()
    addOutput(tx, mvc20TokenLockingScript, 1)

    // mvc20 token genesis
    const newMvc20TokenGenesisScriptBuf = TokenProto.getNewGenesisScript(mvc20TokenGenesis.lockingScript.toBuffer(), Buffer.from(mvc20TokenSensibleID, 'hex'))
    addOutput(tx, mvc.Script.fromBuffer(newMvc20TokenGenesisScriptBuf), inputSatoshis)

    // burn output
    if (burnSats > 0) {
        addOutput(tx, mvc.Script.buildPublicKeyHashOut(burnAddress), burnSats)
    }

    // change mvc(optional)

    // unlock contract
    // mint
    unlockMvc20Mint(tx, prevoutsBuf, mintContract, mvc20Tx, mvc20GenesisTx, tokenScriptBuf, 0, senderAddress, options.expected)

    // mvc20
    const prevMvc20TxInputIndex = 0
    unlockMvc20Main(tx, prevoutsBuf, mvc20Main, 1, mintTx, mvc20Tx, prevMvc20TxInputIndex, prevMvc20Tx, Mvc20Proto.OP_MINT, contractHashArray, mvc20SensibleID, options.mvc20MainExpected)

    // genesis
    unlockMvc20Genesis(tx, prevoutsBuf, mvc20TokenGenesis, 2, 0, mvc20GenesisTx, prevMvc20GenesisTx, mintTx, mvc20Tx, contractHashArray)
}

describe('Test mvc20 contract unlock In Javascript', () => {
    let mvc20Info: Mvc20Proto.Mvc20Info

    before(() => {
        initContractHash()
    });

    beforeEach(() => {
        mvc20Info = {
            maxTokenAmount: BigInt(10000000),
            maxMintAmount: BigInt(1000),
            mintedAmount: BigInt(0),
        }
    })

    it('d1: should success when mint', () => {
        mint(mvc20Info)
    })

    it('d2: should failed when mint overpass max minted amount', () => {
        mvc20Info = {
            maxTokenAmount: BigInt(10000000),
            maxMintAmount: BigInt(1000),
            mintedAmount: BigInt(10000),
        }
        mint(mvc20Info,  {expected: false})
    })

    it('d3: should failed when mint with mvc20TokenAmountAdd', () => {
        mint(mvc20Info,  {mvc20TokenAmountExtra: BigInt(1000), expected: false})
    })

    it('d4: should failed when mint with mvc20 token genesis', () => {
        mint(mvc20Info,  {wrongMvc20TokenGenesis: true, expected: false})
    })

});