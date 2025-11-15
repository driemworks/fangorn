# Quickbeam Encryption flow 

> Note: This is not yet implemented! 

#### Encrypt (Alice)
// input params
$0 < t \leq |\mathcal{U}|$
$m \in \{0, 1\}^*$
$R \in \{0, 1\}^*$ an NP-Relation

// generate ciphertext and add to storage
$(ek, ak) \leftarrow Preprocess(CRS, \mathcal{U}, \{hint_i, pk_i\}_{i \in [\mathcal{U}]})$
$ct \xleftarrow{R} STE.Enc(ek, m, t)$
$cid = Storage.Add(ct)$

// embedded intent
$\bar{m} = \{(R, t), cid\}$
$\bar{cid} = Storage.Add(\bar{m})$

// register with intent storatge
$filename \in \{0, 1\}^d$
$0/1 \leftarrow IntentStore.Register(filename, \bar{cid})$

#### Decrypt (Bob)

Assume Bob knows the filename of some encrypted data, $filename$.

// retrieve ciphertext loc, relation, and intent
$\bar{cid} = IntentStore.Get(filename)$
$\{(R, t), cid\} = Storage.Get(\bar{cid})$

// this needs work... 
$S = DeriveStatement(R)$
Generate a witness $w$ s.t. $(w,s) \in R$

// collect partial decs
$\{pd_1, ..., pd_k\}$ for some $k \geq t$
$b_i \leftarrow PartVerify(pd_i) \forall i \in [k]$ 
if any $b_i == 0$ then reject the share.

// fetch ct
$ct = Storage.Get(cid)$
// TODO: we should probably just store this somewhere
// it could even be embedded in the ciphertext itself
// we should keep contract storage as small as possible 
$(ek, ak) \leftarrow Preprocess(CRS, \mathcal{U}, \{hint_i, pk_i\}_{i \in [\mathcal{U}]})$
$m = DecAggr(CRS, ak, ct, \{pd_1, ..., pd_k\})$