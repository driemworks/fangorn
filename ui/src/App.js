import React, { useState, useEffect } from 'react';
import { ApiPromise, WsProvider } from '@polkadot/api';
import { Buffer } from 'buffer';
import { web3Enable, web3Accounts, web3FromSource } from '@polkadot/extension-dapp';
import { CodePromise, ContractPromise } from '@polkadot/api-contract';
import { Keyring } from '@polkadot/keyring';
import { base64Decode, cryptoWaitReady } from '@polkadot/util-crypto';
import './App.css';
import { BN, BN_ONE, hexToString, hexToU8a, u8aToBn, u8aToString } from "@polkadot/util";
import psp22Metadata from "./psp22.json";
import irisMetadata from './iris.json';
import { Bytes, Struct, TypeRegistry, Vec } from '@polkadot/types';
// import ABI from "./psp22.wasm";

const MAX_CALL_WEIGHT = new BN(1_000_000_000_000).isub(BN_ONE);
const PROOFSIZE = new BN(500_000);
const registry = new TypeRegistry();

const TokenGatedDataApp = () => {
  const [api, setApi] = useState(null);
  const [account, setAccount] = useState(null);
  const [contract, setContract] = useState(null);
  const [status, setStatus] = useState('Ready to connect');
  const [data, setData] = useState([]);
  const [decodedIntents, setDecodedIntents] = useState({});

  const IRIS_CONTRACT_ADDRESS = '5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7';

  const Intent = Struct.with({
    intent_type: 'Text',
    statement: 'Bytes',
  });
  const IntentVec = Vec.with(Intent);

  useEffect(() => {
    connectWallet();
  }, []);

  const connectWallet = async () => {
    const wsProvider = new WsProvider('ws://127.0.0.1:9944');
    const api = await ApiPromise.create({ provider: wsProvider });
    setApi(api);

    const contract = new ContractPromise(api, irisMetadata, IRIS_CONTRACT_ADDRESS);
    setContract(contract);

    await web3Enable('Iris');
    const allAccounts = await web3Accounts();
    // just default to the first
    if (allAccounts.length > 0) setAccount(allAccounts[0]);
  };

  /**
   * Deploy a new contract
   * @returns 
   */
  const deploy = async () => {

    if (!api || !account) return;

    setStatus('Preparing contract...');

    const wasmResponse = await fetch('/psp22.wasm');
    const wasmArray = new Uint8Array(await wasmResponse.arrayBuffer());
    const code = new CodePromise(api, psp22Metadata, wasmArray);

    const constructor = code.tx['new'](
      {
        gasLimit: api.registry.createType('WeightV2', {
          refTime: 1000000000000n,
          proofSize: 131072n,
        }),
        storageDepositLimit: null,
        value: 0,
      },
      100 // initial supply
    );

    // Get injector for signing
    const injector = await web3FromSource(account.meta.source);

    setStatus('Deploying psp22 contract...');

    // Deploy contract
    const unsub = await constructor.signAndSend(
      account.address,
      { signer: injector.signer },
      (result) => {
        if (result.status.isInBlock) {
          setStatus(`Included in block: ${result.status.asInBlock}`);
        } else if (result.status.isFinalized) {
          setStatus(`Finalized: ${result.status.asFinalized}`);
          unsub();

          const record = result.contract;
          if (record) {
            setStatus('Psp22 deployed at: ' + record.address.toString());
          }
        }
      }
    );
  };

  const readAll = async () => {
    if (!contract || !account) return;

    const { _, output } = await contract.query.readAll(account.address, {
      gasLimit: api.createType('WeightV2', {
        refTime: MAX_CALL_WEIGHT,
        proofSize: PROOFSIZE,
      }),
      storageDepositLimit: null,
    });

    if (output?.isOk) {
      const filenames = output.toHuman().Ok;
      console.log('Filenames:', filenames);
      setData(filenames);
    } else {
      console.error('Query failed:', output);
    }
  };

  const read = async (filename) => {
    if (!contract || !account) return;

    const { _, output } = await contract.query.read(account.address, {
      gasLimit: api.createType('WeightV2', {
        refTime: MAX_CALL_WEIGHT,
        proofSize: PROOFSIZE,
      }),
      storageDepositLimit: null,
    }, filename);

    if (output?.isOk) {
      const results = output.toHuman().Ok;
      let intentBytes = hexToU8a(results.intent);
      const decoded = new IntentVec(registry, intentBytes);

      const intents = [];
      // decode each intent statement
      decoded.forEach((intent) => {
        const intentType = intent.get('intent_type').toString();
        let statement = decodeStatement(intentType, intent.get('statement'));
        console.log('Decoded intent with type ' + intentType + 'and statement ' + statement);
        intents.push({ type: intentType, statement: statement });
      });

      setDecodedIntents(prev => ({
        ...prev,
        [filename]: intents
      }));

      setStatus(`Entry read successfully for "${filename}"`);
    } else {
      console.error('Query failed:', output);
    }
  }

  const decodeStatement = (type, statementBytes) => {
    const u8a = statementBytes.toU8a ? statementBytes.toU8a() : statementBytes;

    try {
      if (type === 'Psp22') {

        let data = u8a;

        if (u8a.length > 1) {
          const codec = api.registry.createType('Compact<u32>', u8a);
          const prefixLength = codec.encodedLength;
          // Skip the prefix
          data = u8a.slice(prefixLength);
        }

        return api.createType('(AccountId, u128)', data);
      } else if (type === 'Password') {
        const decoded = api.createType('Vec<u8>', u8a);
        const bytes = decoded.toU8a(true);
        return '0x' + Buffer.from(bytes).toString('hex');
      } else if (type === 'Sr25519') {
        // there is no statement for this intent type
        return '';
      } else {
        const decoded = api.createType('Vec<u8>', u8a);
        const bytes = decoded.toU8a(true);
        return new TextDecoder().decode(bytes);
      }
    } catch (err) {
      console.error('Failed to decode statement:', err);
      return '(invalid statement)';
    }
  };

  return (
    <div className="app">
      <div className='title'>
        Iris Visualizer
      </div>
      <div className='container'>
        <div className='status-container'>
          {status}
        </div>
        <div className='contract-deploy-container'>
          <button onClick={deploy}>
            Deploy Psp22 contract
          </button>
        </div>
        <div className="registry-data">
          <button onClick={readAll} disabled={!contract}>Read All</button>

          <table className="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Data</th>
                <th>Read Intent</th>
                <th>Intent</th>
              </tr>
            </thead>
            <tbody>
              {data.length === 0 ? (
                <tr>
                  <td colSpan="2" className="empty">No data found.</td>
                </tr>
              ) : (
                data.map((item, i) => (
                  <tr key={i}>
                    <td>{i + 1}</td>
                    <td>
                      <pre>{item}</pre>
                    </td>
                    <td>
                      <button onClick={() => read(item)}>Read Intent</button>
                    </td>
                    <td>
                      {decodedIntents[item] ? (
                        <div className="intents-list">
                          {decodedIntents[item].map((intent, idx) => (
                            <div key={idx} className="intent-item">
                              <strong>{intent.type}:</strong>
                              <pre>{JSON.stringify(intent.statement)}</pre>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <em>Click "Read Intent" to decode</em>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default TokenGatedDataApp;
