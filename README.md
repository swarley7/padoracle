# padoracle
An extensible, high-performance framework for exploiting padding oracles in network-based applications.

## Background

A padding oracle occurs in a cryptosystem where the application (the oracle) reveals information about the legitimacy of padded ciphertext. This typically happens in cipher block chaining (CBC) mode.

### CBC Mode and Padding

In CBC mode, the encryption of a block depends on the block preceding it. Before a plaintext block is passed through the block cipher algorithm (like AES), it is XORed with the previous ciphertext block. For the very first block, an Initialization Vector (IV) is used instead.

During decryption, this process is reversed:
1. The ciphertext block passes through the block cipher decryption algorithm, resulting in what is called the **Intermediate State** (or intermediate ciphertext).
2. This Intermediate State is then XORed with the preceding ciphertext block (or the IV) to yield the actual plaintext.

```text
    [Ciphertext n-1] ──────┐
                           │ (XOR)
[Ciphertext n] ───[AES Decryption]───> [Intermediate State n] ──> [Plaintext n]
```

Because block ciphers require equal-length blocks (e.g., 16 bytes for AES), the final plaintext block must be padded. Common standards like PKCS7 use the value of the padding bytes to denote the number of padding bytes added. For example, if 4 bytes of padding are needed, `\x04\x04\x04\x04` is appended. 

When an application decrypts the data, it checks this padding. If the last byte is `\x04`, it verifies that the preceding three bytes are also `\x04`. If they aren't, it throws a "Padding Exception".

### The Attack: Recovering the Intermediate State

A padding oracle vulnerability exists if the application leaks whether the padding was valid or invalid (e.g., via HTTP 500 errors, distinct error messages, or timing differences).

By controlling `[Ciphertext n-1]` (the IV for the current block) and sending it to the oracle, an attacker can manipulate the XOR operation that produces `[Plaintext n]`. 

Because `Plaintext = IntermediateState ^ Ciphertext(n-1)`, we can rearrange the math to:
**`IntermediateState = Plaintext ^ Ciphertext(n-1)`**

**The Decryption Exploit Flow:**
1. We send a forged `Ciphertext n-1` consisting of 15 random bytes and 1 guessed byte (testing values 0-255).
2. The server decrypts `Ciphertext n` into its fixed `Intermediate State`.
3. The server XORs the `Intermediate State` with our forged `Ciphertext n-1`.
4. If the server does **not** throw a padding error, we know that the resulting `Plaintext` ended in a valid padding byte (usually `\x01`).

Since we know the forged byte we sent (`Ciphertext n-1`), and we know the resulting plaintext byte must be `\x01` (to pass the padding check), we can calculate the secret **Intermediate State** byte:
`Intermediate_Byte = Forged_Byte ^ \x01`

Once we have the Intermediate State byte, we simply XOR it with the *actual, original* `Ciphertext n-1` ripped from the network traffic to recover the true Plaintext byte!

By repeating this process from right-to-left, adjusting our forged block to look for `\x02\x02`, then `\x03\x03\x03`, we can decrypt the entire ciphertext block without ever knowing the secret AES key.

### The Attack: Forging Payloads (Encryption)

We can also run this math in reverse. If we want the server to decrypt a block into a specific plaintext (e.g., `admin=true`), we first recover the `Intermediate State` of a dummy block (e.g., all `A`s). 

Once we know the Intermediate State of the dummy block, we calculate what `Ciphertext n-1` *should* be to produce our desired plaintext:
`Forged_Ciphertext(n-1) = IntermediateState ^ Desired_Plaintext`

We then prepend this `Forged_Ciphertext(n-1)` to our dummy block and send it to the server. The server will decrypt it, perform the XOR, and blindly accept our forged plaintext. By chaining these blocks together, we can forge payloads of any length.

## Quick Start Demonstrations

To see `padoracle` in action immediately, you can use the included vulnerable servers in the `examples/` directory.

### 1. HTTP Padding Oracle (AES-CBC)

This server hosts a vulnerable endpoint that leaks padding errors via HTTP 500 status codes.

1. **Start the vulnerable server:**
   ```bash
   go run examples/vuln_http_server.go -p 8080
   ```
   The server will output a sample ciphertext.

2. **Run `padoracle` to decrypt:**
   In another terminal, use the provided ciphertext to recover the plaintext:
   ```bash
   go run padoracle.go -u "http://127.0.0.1:8080/?vuln=<PADME>" -c "<PASTE_CIPHERTEXT_HERE>" -bs 16
   ```

3. **Run `padoracle` to encrypt (forge a payload):**
   You can also use the oracle to encrypt arbitrary data without the key:
   ```bash
   go run padoracle.go -u "http://127.0.0.1:8080/?vuln=<PADME>" -m 1 -p "Forged Payload" -bs 16
   ```
   The tool will output a forged ciphertext that the server will accept as valid.

### 2. TCP Padding Oracle (Custom Protocol)

This server demonstrates a non-HTTP padding oracle that communicates over raw TCP and leaks errors through a specific string (`PADDING_ERROR`).

1. **Start the TCP server:**
   ```bash
   go run examples/vuln_tcp_server.go -p 9000
   ```

2. **Modify `padoracle.go` for TCP:**
   You would need to update `CallOracle` to use `net.Dial("tcp", ...)` and check for the `PADDING_ERROR` string. This is a great exercise to see how extensible the tool is!

## Why `padoracle`?

There are other padding oracle exploitation tools, but `padoracle` focuses on **speed** and **concurrency**.

- `padbuster`: A classic tool, but written in Perl and can be slow.
- `padding-oracle-attack`: A solid Python-based solution, but somewhat inflexible and processes blocks sequentially.

`padoracle` is *fast*. It is built in Go and aggressively parallelizes the attack. It decrypts each block independently and concurrently. It also parallelizes the byte-guessing process using safe and efficient goroutines, meaning it can fire off hundreds of asynchronous requests at once. On a test system, it can decrypt 16 blocks of 16-byte ciphertext in under 1.5 minutes (using 100 threads).

## Usage
`padoracle` is highly extensible, but it requires minor code modifications to teach it how to talk to your specific target.

First, clone the repository:

```bash
git clone https://github.com/swarley7/padoracle.git
cd padoracle
```

### Configuring the Oracle
To adapt the tool to your target application, open `padoracle.go` in your favorite editor. You will need to modify the `testpad` struct's methods to suit your needs:

1. **`EncodePayload`**: Define how the raw byte payload should be encoded before sending it (e.g., Base64, Hex).
2. **`DecodeCiphertextPayload`**: Define how the input ciphertext from the CLI should be decoded into raw bytes.
3. **`CallOracle`**: Implement the HTTP request (or any protocol) that sends the payload to the target.
4. **`CheckResponse`**: Analyze the HTTP response (status code, body text, etc.) to determine if the padding was valid (`true`) or invalid (`false`).

Once modified, build the tool:

```bash
go build
```

Then run it against your target:

```bash
./padoracle -u "http://target.com/vuln?data=<PADME>" -c "YOUR_ENCODED_CIPHERTEXT" -bs 16 -T 100
```

Use the `-h` flag to see all available options (such as `-m 1` for encryption mode).

## Examples

!["Busting pad oracles"](./sample.png)
!["Finished"](./sample_finished.png)

## Credits
Built as an exercise in lateral thinking and Go concurrency. 
