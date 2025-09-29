``` mermaid
flowchart TD
  subgraph Tangle AVS
    T1(Job request from smart contract)
    T2[Select Worker Committee or Broadcast Job]
    T3[Verify Aggregated Result]
    T4[Distribute Payment]
  end

  subgraph STE Network
    S1[Workers Listen for Jobs]
    S2[Compute Partial Decryptions]
    S3[Aggregator Combines Results]
    S4[Return to AVS]
  end

  SmartContract -->|Decrypt Condition Trigger| T1 --> T2
  T2 --> S1
  S1 --> S2 --> S3 --> S4 --> T3 --> T4 --> Workers
```