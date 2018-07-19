# padoracle
An extensible framework for exploiting padding oracles in network-based applications.

## Background
A padding oracle occurs in a cryptosystem where something (the oracle) reveals information about the legiticamy of padded ciphertext. In cipher block chaining (CBC) mode, the IV is typically the first block of the ciphertext (or might be kept secret for "reasons"). The ciphertext of the preceeding block forms the IV of the current block.

Since block ciphers require equal length ciphertext blocks, the final block of plaintext must be padded out to meet the required blocksize. Typical padding modes include PKCS5 and PKCS7 - both of which are pretty much identical, except PKCS5 is used for 8 byte blocks, whereas PKCS7 can be used for `n < 256` byte block sizes. Both modes basically use the last byte of cleartext to denote how many bytes of padding are included within the block.

For example, given the cleartext `AAAA\x04\x04\x04\x04`, the last byte (`\x04`) tells the decryption routine that there are 4 bytes of padding which will need to be removed to return the original message. This operation, in conjunction with the fact that the previous block's ciphertext forms the IV for the current block is what the padding oracle attack exploits.

## Yes, but there's other padding oracle exploitation tools?

Sure there are. In fact, I've used some of them before!

- `padbuster`: works ok, but it's fairly old and dated, and written in Perl (which is a Write-Only language) 
- `padding-oracle-attack`: very good python-based solution. Easy to modify to suit specific pad-oracle requirements. A bit inflexible in how it approaches the problem, and, most importantly, it's very slow.

`padoracle` is *fast*. On my test system it decrypted 16 blocks of 16 byte ciphertext in under 1.5 mins (using 100 threads). The reason for this speed increase, is that each block is decrypted independently of the others, in parallel. There is nothing in the attack that requires each block to be decrypted sequentially.



## Usage
`padoracle` is super extensible and can be made to suit any requirements. However, it does require some modifications in order to make it work. First thing's first; clone the repo.

`git clone https://github.com/swarley7/padoracle.git && cd padoracle`

Next, install the dependencies (hopefully there's no errors):

`go get -u`

Next comes the hard part (it's not that hard really). Open `./libpadoracle/modifyme.go` in your favourite editor and get modifying!



## Examples

## Credits

## Donate?
