# DawgCTF Protocol Analysis — Writeup

Manual: https://github.com/UMBCCyberDawgs/dawgctf-sp26/blob/main/Protocol%20Analysis%20(1-9)/Protocol_Analysis_chals.pdf

Server: `https://protocols.live` — see `client.py` for the reusable HTTP wrapper.
Each challenge lives in `chal-N/solve.py`.

This was largely an experiment in utilizing AI to solve repetitive tasks as a way to simulate what an attacker could do with just Claude code. The results were surprising. Aside from adjusting the HTTP wrapper, I was able to get through all 9 problems in 3 problem chunks with no human intervention in less than 2hrs.  

## Challenge 1 — Can You Hear Me?

> Alice and Bob are having a discussion. Perhaps you can listen for a flag?
>
> Protocol key: `A = alice`, `B = bob`
>
> ```
> Alice                                                 Bob
> send: "Hello",B,"this is",A,"give me the flag"
>                                recv: "Hello",B,"this is",A,"give me the flag"
>                                                     send: "here it is",[FLAG]
> recv: "here it is",[FLAG]
> ```

**Protocol:** Plaintext. Alice sends a greeting naming herself and Bob; Bob replies with `"here it is", [FLAG]`.

**Attack:** None needed. Act as a transparent relay.

Open a connection with `POST /model/1` to get a `conn_id`, then call `POST /alice` with empty content to pull Alice's opening `send`: `t:Hello|n:bob|t:this is|n:alice|t:give me the flag`. Hand that straight to `POST /bob`, which satisfies his `recv`; his next step is a `send`, so the response comes back as `t:here it is|t:DawgCTF{...}`.

**Flag:** `DawgCTF{PR0T0C0LS_R_3ZPZ}`

**Notes:** Posting `/alice` with empty content is a cheap way to pull Alice's first `send` without feeding her anything — it works whenever an entity's next step is a send, and it stays useful throughout the challenge set. The response format is pipe-separated typed items (`t:`, `n:`, `k:`, `d:`), and the flag always arrives as a `t:` item.

## Challenge 2 — Liar

> Alice and Bob are having another discussion. But Bob only want to give this flag to charlie. Can you figure this out?
>
> Protocol key: `A = alice`, `B = bob`, `C = charlie`
>
> ```
> Alice                                                 Bob
> send: "Hello",B,"this is",A,"give me the flag"
>                                recv: "Hello",B,"this is",C,"give me the flag"
>                                                     send: "here it is",[FLAG]
> recv: "here it is",[FLAG]
> ```

**Protocol:** Same shape as chal 1 but Bob only accepts the greeting if the sender name field is `charlie`, not `alice`. Nothing is signed or encrypted.

**Attack:** Skip Alice entirely. Hand Bob a forged greeting with `n:charlie` and he happily `send`s the flag.

After `POST /model/2` for a `conn_id`, we go straight to `POST /bob` with `t:Hello|n:bob|t:this is|n:charlie|t:give me the flag` — no Alice involvement at all — and his response contains `t:here it is|t:DawgCTF{...}`.

**Flag:** `DawgCTF{CH4NG3_0F_PL4N5}`

**Notes:** This reinforces the manual's core rule that each entity only checks its own script: Alice is irrelevant here because we never talk to her, and whenever a `recv` is the only gate on the flag we should go straight to that side with forged content. Plaintext name fields are trivially forgeable, and authenticity won't start mattering until signatures and certs enter the picture.

## Challenge 3 — Missing

> Alice and Bob are not having a discussion, as Alice is gone. Perhaps there is a still a flag out there?
>
> Protocol key: `A = alice`, `B = bob`
>
> ```
> Alice                                                 Bob
>                                recv: "Hello",B,"this is",A,"give me the flag"
>                                                     send: "here it is",[FLAG]
> ```

**Protocol:** Alice has no script at all; only Bob participates. Bob `recv`s the standard greeting `"Hello",B,"this is",A,"give me the flag"` then `send`s `"here it is",[FLAG]`.

**Attack:** None beyond impersonation. With Alice absent there's nothing to relay — the adversary is the only sender. Feed Bob the greeting directly and he returns the flag.

After `POST /model/3`, a single `POST /bob` with `t:Hello|n:bob|t:this is|n:alice|t:give me the flag` elicits his response `t:here it is|t:DawgCTF{...}`.

**Flag:** `DawgCTF{N0_0N3_3LS3_H0M3}`

**Notes:** "Alice is gone" just means her script is empty, not that `/alice` is disabled — we simply never call it. This reinforces chal 2's pattern: when the flag is gated only by a `recv`, speak directly to that entity and skip the other side entirely.

## Challenge 4 — Real Security!

> Alice and Bob have figured out how to use encryption so they can exchange flags securely! They are pretty sure they are using it right.
>
> Protocol key: `A = alice`, `B = bob`
>
> ```
> Alice                                                 Bob
> send: "Hello",B,"this is",A,"send the flag
>        encrypted with this symmetric key and nonce",k,n
>                                recv: "Hello",B,"this is",A,"send the flag
>                                       encrypted with this symmetric key and nonce",k,n
>                                                     send: "here it is",{[FLAG]}k
> recv: "here it is",{[FLAG]}k
> ```

**Protocol:** Alice sends Bob a greeting plus a symmetric key `k` and nonce `n` in the clear, asking Bob to reply with `{[FLAG]}k`. No authentication, no key wrapping.

**Attack:** Pure eavesdrop. The key and nonce travel in plaintext, so once Bob returns the ciphertext, `/util/sym_decrypt` with the captured `k`/`n` reveals the flag. No forgery required.

Open the connection with `POST /model/4`, then `POST /alice` empty to pull her send: `t:Hello|n:bob|t:this is|n:alice|t:send me the flag encrypted under this symetric key and nonce|k:<K>|d:<N>`. Forward that to `POST /bob` and he replies `t:here it is|d:<CT>`. Finally hand `k:<K>|d:<N>|d:<CT>` to `POST /util/sym_decrypt` and the flag falls out.

**Flag:** `DawgCTF{N0T_S0_S3CR3T_K3Y}`

**Notes:** The `/util/*` endpoints require `conn_id` to be a JSON **integer**, not a string — the validator 422s strings — whereas `/alice` and `/bob` accept the server-issued id as-is, so `client.py` now hardcodes `conn_id: 0` for util calls. Util content uses the same typed pipe format as protocol messages (e.g. `sym_decrypt` wants `k:<hex>|d:<nonce>|d:<ct>`, not bare values). The broader lesson for later challenges: if a key is ever exchanged without being wrapped under something only the receiver can open, assume the channel is broken.

## Challenge 5 — Is This Real?

> Alice and Bob are using this cool new thing called asymmetric cryptography! Alice isn't gonna leak her private key, so how could anyone intercept the flag?
>
> Protocol key: `A = alice`, `B = bob`, `X = any name`
>
> ```
> Alice                                                 Bob
> send: "Hello",B,"this is",A,"send the flag
>        encrypted with this asymmetric key",pubA
>                                recv: "Hello",B,"this is",A,"send the flag
>                                       encrypted with this asymmetric key",pubX
>                                                     send: "here it is",{[FLAG]}pubX
> recv: "here it is",{[FLAG]}pubA
> ```

**Protocol:** Same shape as chal 4, but the greeting carries an asymmetric public key instead of a symmetric key + nonce. Bob's `recv` expects `pubX` for *any* name X — there's no cert binding the key to Alice — and Bob replies with `{[FLAG]}pubX`.

**Attack:** Key substitution. The adversary generates their own asymmetric keypair via `/util/gen_asym_key_pair`, sends Bob the greeting with their own `pubX` in place of `pubA`, and decrypts the returned ciphertext with the matching private key.

First, `POST /util/gen_asym_key_pair` with empty content returns `t:public|k:<pub>|t:private|k:<priv>`. Open the connection with `POST /model/5`, then go straight to `POST /bob` with `t:Hello|n:bob|t:this is|n:alice|t:send the flag encrypted under this asymetric key|k:<pub>` — our own pub, no Alice needed. Bob replies `t:here it is|d:<CT>`, and `POST /util/asym_decrypt` with `k:<priv>|d:<CT>` yields the flag.

**Flag:** `DawgCTF{C3RT1F13D_1NS3CUR3}`

**Notes:** Alice's wire text reads `"send the flag encrypted under this asymetric key"` — typo'd (`asymetric`) and using `under`, not `with` as the manual shows — so when a hand-built greeting gets rejected, pull the entity's own `send` first and copy the literal text. I briefly convinced myself that the util labels for asymmetric ops were reversed (that `asym_encrypt` took a private key and `asym_decrypt` took the public), but that was a misreading corrected in chal 6; the labels don't matter here only because Bob treats whichever key is handed to him as `pubX`, so the pair round-tripped for this specific flow. The flag name says the quiet part: without a cert binding the key to a name, asymmetric crypto alone buys you nothing against a man-in-the-middle, and chal 6 onward brings `/util/get_cert` into play to address exactly that.

## Challenge 6 — Sneedham-Chucker

> Chuck needs to send Sneed an urgent message regarding the name of their store, but he doesn't want any city slickers listening in. There may be a flag abound.
>
> Protocol key: `A = sneed`, `B = chuck`, `X = any name`, `nX = nonce of entity X`, `h(x + y) = hash of data x and y` (+ indicates concatenation without pipes or colons)
>
> ```
> Alice                                                 Bob
>                                                     send: pubB, B, certB
> recv: pubX, X, certX
> send: {nA, pubA, A, certA}pubX
>                                      recv: {nA, pubA, A, certA}pubB
>                                                     send: {nA, nB}pubA
> recv: {nA, nX}pubA
> send: {nX}pubX
>                                                     recv: {nB}pubB
>                                                     send: {[FLAG]}h(nA+nB)
> recv: {[FLAG]}h(nA+nX)
> ```

**Protocol:** Needham-Schroeder Public-Key between sneed (A, on the `/alice` endpoint) and chuck (B, on `/bob`). Chuck opens with `pubB, B, certB`; sneed expects `pubX, X, certX` then sends `{nA, pubA, A, certA}pubX`; chuck responds with `{nA, nB}pubA`; sneed replies with `{nX}pubX`; chuck finally sends `{[FLAG]}h(nA+nB)`.

**Attack:** Classic Lowe MITM. Run one session as "eve" against sneed in parallel with sneed's legitimate session against chuck, relaying (and re-sealing) the authentication nonces so sneed does the nB decryption we can't do ourselves.

Start by building eve: `POST /util/gen_asym_key_pair` for `(pub_e, priv_e)`, then `POST /util/get_cert` with `k:pub_e|n:eve` for `cert_e` (eve isn't on the denylist). Open the model connection, pull chuck's opener via `POST /bob` empty — capture `pub_c` from his `k:pub_c|n:chuck|d:cert_c`. Introduce eve to sneed via `POST /alice` with `k:pub_e|n:eve|d:cert_e`; she returns `{nA, pub_a, sneed, cert_a}pub_e`, which we open with `/util/asym_decrypt` under `priv_e` to recover `nA` and `pub_a`. Re-seal `d:nA|k:pub_a|n:sneed|d:cert_a` under `pub_c` with `/util/asym_encrypt` and `POST /bob`; chuck replies with `{nA, nB}pub_a`, opaque to us. Hand that ciphertext straight to `/alice` as sneed's `recv: {nA, nX}pubA` — she opens it, matches `nA` to her own, assumes the second slot is eve's nonce, and emits `{nX}pub_e` = `{nB}pub_e`, which we decrypt with `priv_e` to recover `nB`. Finally seal `d:nB` under `pub_c`, post to `/bob`, and chuck sends the flag as `{[FLAG]}h(nA+nB)` on the wire in a single `d:` blob; derive `key = hash_data(nA_hex || nB_hex)` and `nonce = key[:24_hex]`, feed `/util/sym_decrypt`, and the flag returns.

**Flag:** `DawgCTF{FORM3RLY_S3CUR3}`

**Notes:** This overturns the chal-5 note on asymmetric key directions — empirically `/util/asym_encrypt` takes the **public** key and `/util/asym_decrypt` takes the **private** key, standard RSA-OAEP semantics; the manual labels them backwards, and verification with a known plaintext showed that only `encrypt(pub)` + `decrypt(priv)` works while the opposite pair 400s. `/hash_data` hashes the **ASCII hex string** rather than the raw binary bytes (`hash_data("deadbeef")` equals `sha256(b"deadbeef")`, not `sha256(bytes.fromhex("deadbeef"))`), which happens to be correct here because the protocol's `+` is literal hex concatenation of the two 32-byte nonces. The flag's symmetric encryption ships as pure ct+tag with no nonce field on the wire — the server derives both the key and the nonce from the same hash, with the nonce being the first 12 bytes (24 hex chars) of `h(nA+nB)`, worth remembering for any future `{m}h(...)` construction. The `/util/get_cert` denylist is exactly `{alice, bob, chuck, sneed}`, so "eve" (or any other name) certs freely and makes a reusable pocket identity for NSPK-style attacks. The deep reason Lowe's attack works: sneed doesn't bind the second nonce in `{nA, nX}pubA` to any identity — she just assumes the second slot is whoever she initially received X from, which is exactly how she decrypts `nB` on our behalf.

## Challenge 7 — Mediation

> Bob is trying to talk to Alice to give her a flag, but Alice isn't having any of it, ever since their conversations leaked all those flags before. Perhaps you can help them communicate?
>
> Protocol key: `A = alice`, `B = bob`, `X = any name`, `nX = nonce of entity X`
>
> ```
> Alice                                                 Bob
> send: pubA, A, certA, nA
>                                          recv: pubA, A, certA, nA
>                                 send: pubB, B, certB, nB, {B, nB, nA}privB
> recv: pubX, X, certX, nX, {X, nX, nA}privX
> send: {A, nX, nA}privA
>                                                     recv: {A, nB, nA}privA
>                                                     send: [FLAG]
> ```

**Protocol:** Mutual challenge-response with signatures. Alice opens with `pubA, alice, certA, nA`. Bob replies `pubB, bob, certB, nB, {bob, nB, nA}privB`. Alice's recv accepts `pubX, X, certX, nX, {X, nX, nA}privX` for *any* name X. Alice then sends `{alice, nX, nA}privA`. Bob's final recv demands `{alice, nB, nA}privA`, and only then sends `[FLAG]` as plaintext.

**Attack:** Alice-as-signing-oracle. Alice produces a signature over `(alice, nX, nA)` for whatever `nX` her peer presents. Impersonate "eve" to Alice but feed her `nX = nB` (Bob's nonce captured from his own send). Alice's resulting signature is byte-identical to the `{alice, nB, nA}privA` Bob demands. Forward it and Bob drops the flag.

Build eve's keypair and cert (name not on the denylist), open a connection with `POST /model/7`, and pull Alice's opener via `POST /alice` empty — capture `nA` from her `pubA, alice, certA, nA`. Forward that to `POST /bob` to obtain his `pubB, bob, certB, nB, sigB`; capture `nB` (we never need `sigB`). Sign `n:eve|d:<nB>|d:<nA>` under eve's priv to produce `sig_e`, and feed Alice `k:pubE|n:eve|d:certE|d:<nB>|d:<sig_e>`. Alice returns `d:<sig_a>` — exactly `sign(privA, "n:alice|d:<nB>|d:<nA>")`. Hand that to `POST /bob` as `d:<sig_a>` and he sends `t:DawgCTF{...}`.

**Flag:** `DawgCTF{F33L1NG_1NS3CUR3}`

**Notes:** The canonical signing format for items in a protocol tuple is the same typed pipe format used on the wire — `{X, nX, nA}privX` serializes to `asym_sign(privX, "n:X|d:nX|d:nA")` — which matches the convention chal 6 used for `asym_encrypt` and is the safe default for every `{…}priv` from here on. The attack works because Alice binds the signed tuple to the nonce *she received*, not to the name field on the wire; she never checks that the peer's claimed `nX` is fresh or that it isn't already someone else's nonce, which is a textbook reuse-as-oracle pattern. Any protocol where a principal signs `(peer_data, own_data)` with attacker-controlled `peer_data` is a signing oracle for that tuple shape. No decryption was needed anywhere in this solve — purely signature reflection, and the flag itself ships as bare plaintext `t:…`.

## Challenge 8 — Reflection

> Bob and Alice are talking again, but this time they messed up and are both in the same roles of the protocol. Bob still has a flag though, can you get it?
>
> Protocol key: `A = alice`, `B = bob`, `X = any name`, `nX = nonce of entity X`
>
> ```
> Alice                                                 Bob
> send: pubA, A, certA
>                                                     send: pubB, B, certB
> recv: pubX, X, certX, nX1
>                                              recv: pubA, A, certA, nA
> send: nA, {X, nX1, nA}privA
>                                              send: nB, {A, nA, nB}privB
> recv: nX2, {A, nA, nX2}privX
>                                              recv: nA2, {A, nB, nA2}privA
>                                                     send: [FLAG]
> ```

**Protocol:** Mutual challenge-response with signatures, but Alice and Bob are *both* put into the same initiator role. Both open with `pub, name, cert`; both then `recv` the peer's `pub, name, cert, nonce`; both `send` their own nonce plus a signed `{X, nX1, selfNonce}` triple; both close by `recv`ing `otherNonce, {A, myNonce, otherNonce}privA`. Bob is the only one with a flag to reveal after his final recv.

**Attack:** Full key substitution, not a classical reflection. Two bits of leverage combine: (1) `/util/get_cert`'s denylist is case-sensitive — `alice` is blocked, `Alice` certs freely — and Bob's step-2 name check is case-insensitive, so a cert for "Alice" binding *our* pub passes his cert check and replaces his stored `pubA` with a key we own. (2) The server's `{…}priv` serialization uses the **signer's own name** as the first field regardless of the script's `{A, …}` / `{X, …}` notation — so real Alice's sig always starts with `n:alice`, but Bob's step-4 verification against his stored "pubA" expects text starting with `n:bob`. Substitute pubA with `pub_e`, then forge the exact text Bob wants under `priv_e`.

Generate an eve keypair, then `get_cert` with `k:pub_e|n:Alice` (capital A slips past the denylist) for `cert_e`. Open the connection with `POST /model/8`, and send `POST /bob` empty just to confirm he's at step 1 — his opener `k:pubB|n:bob|d:certB` isn't otherwise needed. Now send `POST /bob` with `k:pub_e|n:Alice|d:cert_e|d:<nA>` for any 64-hex `nA` we choose: Bob's name check matches "Alice" case-insensitively, his cert verifies under the PKI root (the cert is genuine; it just binds `pub_e` to "Alice"), and he stores `pub_e` as his `pubA`. He emits `d:nB|d:sig_bob`. Forge `sig = asym_sign(priv_e, "n:bob|d:<nB>|d:<nA>")` — matching the canonical text Bob's verifier will produce — and send `POST /bob` with `d:<nA>|d:<sig>`. He verifies against his stored `pub_e`, the text matches, and he sends `t:DawgCTF{…}`.

**Flag:** `DawgCTF{4SK_4ND_U_SH4LL_R3C31V3}`

**Notes:** `/util/get_cert`'s denylist is case-sensitive. `Alice`, `ALICE`, `alice\x00`, `alic`, and `alicee` all cert successfully, while only the exact byte strings `alice`, `bob`, `chuck`, and `sneed` are blocked; entity-side name checks are case-insensitive, so `Alice` is interchangeable with `alice` once you're inside the protocol, and this is the first challenge where that gap actually matters. The canonical sig text always uses the **signer's** name, not the script's variable: the PDF writes Alice's send as `{X, nX1, nA}privA` and Bob's verify as `{A, nB, nA2}privA` so you'd expect both to canonicalize as `n:alice|…` / `n:X|…`, but in practice the server puts the *self* name first (Alice signs `n:alice|d:nX1|d:nA`, and Bob verifies against `n:bob|d:nB|d:nA2`) which I verified with `asym_verify` (Alice's real sig only passes under `n:alice|…`, and Bob's step 4 only accepts a forgery under `n:bob|…`). This is exactly what breaks the obvious reflection attack (feed Alice her own cert with `nX1 = nB` so she signs `{alice, nB, nA}privA`): her sig starts with `n:alice` but Bob wants `n:bob`, so they never match no matter how you line up the nonces. That forces a caveat on the chal-7 note — the "peer_data, own_data" signing-oracle framing only helps when the verifier and signer are the same principal; here Alice and Bob are distinct despite symmetric roles, which is why substitution is needed instead of reflection. Also: Bob doesn't bind `nA2` to his step-2 `nA` — we passed them as the same value for convenience but nothing cross-checked them; the only values bound inside the sig text are his own stored `nB` and whatever we put in the msg's first `d:` slot. `send_alice` is never called in this solve, because real Alice has no role in Bob's flag-drop once we convince Bob someone else is her.

## Challenge 9 — Oracle

> Final challenge. In this one, Alice will stay in her last recv-send state infinitely. Can you get the flag?
>
> Protocol key: `A = alice`, `B = bob`, `X = any name`, `m = any message`
>
> ```
> Alice                                                 Bob
> send: pubA, A, certA
>                                                     recv: pubA, A, certA
>                            send: pubB, B, certB, {{[FLAG]}pubA, B}pubA, A
> recv: pubX, X, certX, {{m}pubA, X}pubA, A
> send: pubA, A, certA, {{m}pubX, A}pubX, X
> ```

**Protocol:** Bob opens `recv: pubA, A, certA` then `send: pubB, B, certB, {{[FLAG]}pubA, B}pubA, A` — a once-only flag drop doubly wrapped under `pubA`. Alice loops in a single `recv` / `send` pair forever: given `pubX, X, certX, {{m}pubA, X}pubA, A`, she decrypts the inner `{m}pubA` with `privA` and re-sends `pubA, A, certA, {{m}pubX, A}pubX, X` — i.e. she hands back `m` re-encrypted under whatever key you showed up with.

**Attack:** Alice is a full decryption oracle for any ciphertext under `pubA`. Stuff a target ciphertext into the "inner" slot wrapped in an outer layer built with `/util/asym_encrypt` under `pubA` and name "eve"; Alice returns the plaintext re-sealed under `pubE`. Two calls: first peel Bob's outer wrapper (recovering `d:<{FLAG}pubA>|n:bob`), then decrypt the revealed `{FLAG}pubA`.

Open the connection with `POST /model/9` and `POST /alice` empty to capture her opener `k:pubA|n:alice|d:certA` — we need the real `certA` and can't fabricate it (alice is on the denylist), but bootstrapping from Alice's own `send` gives us the exact triple for free. Forward that to `POST /bob`; he emits `k:pubB|n:bob|d:certB|d:<bob_outer>|n:alice` and we capture `bob_outer`. Generate an eve keypair and `get_cert` for name "eve". For the first oracle call, build `outer1 = asym_encrypt(pubA, "d:<bob_outer>|n:eve")` and send Alice `k:pubE|n:eve|d:certE|d:<outer1>|n:alice`; she returns `k:pubA|n:alice|d:certA|d:<sent1>|n:eve`. Decrypt `sent1` with `privE` to get `d:<ct_m>|n:alice`, then decrypt `ct_m` with `privE` to get `d:<flag_ct>|n:bob` — that inner `flag_ct` is `{FLAG}pubA`. For the second oracle call, repeat the same shape with `flag_ct` in the inner slot: `outer2 = asym_encrypt(pubA, "d:<flag_ct>|n:eve")`, send to Alice, and walk the nested decryption again; the final `asym_decrypt` under `privE` returns `t:DawgCTF{...}`.

**Flag:** `DawgCTF{ST4R3_1NTO_TH3_VO1D}`

**Notes:** `/util/asym_decrypt` preserves the **typed wire format** of whatever was encrypted — when Alice encrypts her plaintext-form `m` under `pubE`, the decrypt returns `d:<hex>|n:<name>` directly rather than something wrapped in `t:`, so `parse(result)["d"][0]` is the right extractor and only terminal human strings (FLAG, human text) come back as `t:<...>`. When Alice "re-encrypts `m`" under `pubX` she's re-serializing a parsed plaintext, not forwarding bytes, and any valid typed-pipe plaintext round-trips cleanly, including nested `d:` hex blobs — that's what makes the oracle chainable. The `A` at the tail of Alice's recv (`…, A`) is a literal `n:alice` item on the wire, and omitting it 400s; same for Bob's tail `n:alice` in his send frame. Bob's `recv` needs `pubA, A, certA`, the one triple we can't fabricate from `/util/get_cert` (alice is on the denylist), so pulling Alice's empty-content opening gives us the exact triple gratis — and any chal that needs a "real" `certA` can bootstrap the same way as long as Alice's script starts with a `send` of her own cert. Decryption oracles beat signing oracles (chal 7) for flexibility: because Alice re-wraps under our chosen key, we convert "any ciphertext under `pubA`" into "any ciphertext under `pubE`," and `privE` finishes the job — if a loop ever re-encrypts attacker-controlled plaintext, assume oracle game over.
