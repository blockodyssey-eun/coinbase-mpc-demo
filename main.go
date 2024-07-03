package main

import (
	"coinbase_tecdsa_2/lib/eth"
	iodkg "coinbase_tecdsa_2/lib/io_dkg"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/sign"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/sha3"
)

const payloadKey = "direct"

func loadENV() (string, string) {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	return os.Getenv("INFURA_KEY"), os.Getenv("PRIVATE_KEY")
}

func main() {
	INFURA_KEY, _ := loadENV()

	infuraURL := fmt.Sprintf("https://sepolia.infura.io/v3/%s", INFURA_KEY)
	client, err := ethclient.Dial(infuraURL)
	if err != nil {
		log.Fatalf("failed to connect to the Ethereum client: %v", err)
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	const dkgFilename = "dkg_data.json"

	var aliceOutput *dkg.AliceOutput
	var bobOutput *dkg.BobOutput
	var address common.Address

	curve := curves.K256()

	// make dkg
	if _, err := os.Stat(dkgFilename); os.IsNotExist(err) {
		aliceDkg, bobDkg, _, address := full_dkg(curve)
		err = iodkg.SaveDkgData(aliceDkg, bobDkg, address, dkgFilename)
		if err != nil {
			log.Fatalf("Failed to save DKG data: %v", err)
		}
		aliceOutput = aliceDkg.Output()
		bobOutput = bobDkg.Output()
	} else {
		aliceOutput, bobOutput, address, err = iodkg.LoadDkgData(dkgFilename, curve)
		if err != nil {
			log.Fatalf("Failed to load DKG data: %v", err)
		}
	}

	// inject test ether
	amount := big.NewInt(10000000000000) // 0.0001 Ether
	// injectTestEther(client, PRIVATE_KEY, address, amount)

	signer := types.NewEIP155Signer(chainID)
	tx, txHash := generateRlpEncodedTx(
		*client,
		signer,
		address,
		common.HexToAddress("0x1139F74a15f25f7503B30cd36D527DA5A6D3E15D"),
		new(big.Int).Div(amount, big.NewInt(3)),
	)

	// sign
	signature := full_sign(curve, txHash, aliceOutput, bobOutput)
	signatureBytes := append(signature.R.Bytes(), signature.S.Bytes()...)

	pkA := curve.ScalarBaseMult(aliceOutput.SecretKeyShare)
	computedCompressedPublicKey := pkA.Mul(bobOutput.SecretKeyShare).ToAffineUncompressed()
	computedPublicKeyByte := hexutil.Encode(computedCompressedPublicKey)
	unmarshalPublickey, _ := crypto.UnmarshalPubkey(computedCompressedPublicKey)
	computedAddress := crypto.PubkeyToAddress(*unmarshalPublickey)
	fmt.Println("publicKey:", computedPublicKeyByte)
	fmt.Println("address:", computedAddress)

	ecCurve, _ := curve.ToEllipticCurve()
	x := new(big.Int).SetBytes(computedCompressedPublicKey[1:33])
	y := new(big.Int).SetBytes(computedCompressedPublicKey[33:])
	publicKeyPoint := &curves.EcPoint{
		Curve: ecCurve,
		X:     x,
		Y:     y,
	}

	isVerifiedECDSA := curves.VerifyEcdsa(publicKeyPoint, crypto.Keccak256(txHash[:]), signature)
	fmt.Printf("is valid ECDSA: %t\n", isVerifiedECDSA)

	isVerified := crypto.VerifySignature(computedCompressedPublicKey, crypto.Keccak256(txHash), signatureBytes)
	fmt.Printf("is valid signature: %t\n", isVerified)

	// V
	var recid int64 = 0
	V := byte(big.NewInt(recid).Uint64())
	signatureBytes = append(signatureBytes, V)
	signedTx, err := tx.WithSignature(signer, signatureBytes)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}
	sender, err := types.Sender(signer, signedTx)
	if err != nil {
		log.Fatalf("Failed to recover sender: %v", err)
	}
	fmt.Printf("Recovered sender: %s\n", sender.Hex())
	// fmt.Println("\nBefore signing:")
	// before_v, before_r, before_s := signature.V, signature.R, signature.S
	// fmt.Printf("v: %d\n", before_v)
	// fmt.Printf("r: %x\n", before_r.Bytes())
	// fmt.Printf("s: %x\n", before_s.Bytes())

	// // 공개 키 복구
	// pubKey, err := crypto.Ecrecover(txHash, signatureBytes)
	// if err != nil {
	// 	log.Fatalf("Failed to recover public key: %v", err)
	// }

	// // 공개 키에서 주소 추출
	// pubKeyECDSA, _ := crypto.UnmarshalPubkey(pubKey)
	// recoveredAddr := crypto.PubkeyToAddress(*pubKeyECDSA)
	// fmt.Printf("Recovered address: %s\n", recoveredAddr.Hex())

	// // check verify
	// signatureBytes := append(signature.R.Bytes(), signature.S.Bytes()...)
	// // verification_by_goethereum := crypto.VerifySignature(, txHash, signatureBytes)
	// fmt.Println("Publickey:", bobOutput.PublicKey.ToAffineCompressed())
	// isVerified := verifySignature(bobOutput.PublicKey.ToAffineUncompressed(), txHash, signatureBytes)
	// fmt.Println("\nis Verified:", isVerified)

	// // make signed tx
	// signatureBytes = append(signatureBytes, byte(signature.V))
	signedRawTx, _ := tx.WithSignature(signer, signatureBytes)
	// signedRawTxBytes, _ := rlp.EncodeToBytes(signedRawTx)
	// signedRawTxHex := hexutil.Encode(signedRawTx)
	// fmt.Println("\nsignedRawTxHex:", signedRawTxHex)

	// fmt.Println("\nAfter signing:")
	// after_v, after_r, after_s := signedRawTx.RawSignatureValues()
	// fmt.Printf("v: %d\n", after_v)
	// fmt.Printf("r: %x\n", after_r)
	// fmt.Printf("s: %x\n", after_s)

	printSignedTxAsJSON(signedRawTx)

	// if err != nil {
	// 	log.Fatalf("failed to add signature to transaction: %v", err)
	// }
	// // 서명 후 VRS 값 출력

	// rlpEncodedSignedTx, _ := signedTx.MarshalBinary()
	// fmt.Println("signedTx: ", common.Bytes2Hex(rlpEncodedSignedTx))

	// // send signed tx
	// sender, err := signer.Sender(signedTx)
	// if err != nil {
	// 	log.Fatalf("Failed to derive sender from signed transaction: %v", err)
	// }
	// fmt.Printf("Derived sender from signed transaction: %s\n", sender.Hex())
	// err = eth.SendSignedTransaction(client, signedTx, true)
	// if err != nil {
	// 	log.Fatalf("failed to send signed transaction: %v", err)
	// }
}

func verifySignature(unCompressedAffinePublicKey []byte, digest []byte, signature []byte) bool {
	return crypto.VerifySignature(unCompressedAffinePublicKey, digest, signature)
}

func injectTestEther(client *ethclient.Client, privateKey string, toAddress common.Address, amount *big.Int) {
	pk, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	signedTx, err := eth.SignTransactionWithPrivateKey(client, pk, toAddress, amount)
	if err != nil {
		log.Fatalf("failed to sign transaction: %v", err)
	}

	err = eth.SendSignedTransaction(client, signedTx, true)
	if err != nil {
		log.Fatalf("failed to send signed transaction: %v", err)
	}
}

func generateRlpEncodedTx(client ethclient.Client, signer types.Signer, fromAddress common.Address, toAddress common.Address, amount *big.Int) (*types.Transaction, []byte) {
	// sign
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("failed to get nonce: %v", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("failed to get gas price: %v", err)
	}

	gasLimit := uint64(21000)
	tx := eth.GenerateTransaction(nonce, toAddress, amount, gasLimit, gasPrice, nil)
	txHash, _ := rlp.EncodeToBytes([]interface{}{
		tx.Nonce(),
		tx.GasPrice(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		signer.ChainID(), uint(0), uint(0),
	})
	return tx, txHash
}

func full_dkg(curve *curves.Curve) (*dkg.Alice, *dkg.Bob, string, common.Address) {
	aliceDkg := dkg.NewAlice(curve)
	bobDkg := dkg.NewBob(curve)

	seed, err := bobDkg.Round1GenerateRandomSeed()
	if err != nil {
		log.Fatalf("Error in Round1GenerateRandomSeed: %v", err)
	}

	round3Output, err := aliceDkg.Round2CommitToProof(seed)
	if err != nil {
		log.Fatalf("Error in Round2CommitToProof: %v", err)
	}

	proof, err := bobDkg.Round3SchnorrProve(round3Output)
	if err != nil {
		log.Fatalf("Error in Round3SchnorrProve: %v", err)
	}

	proof, err = aliceDkg.Round4VerifyAndReveal(proof)
	if err != nil {
		log.Fatalf("Error in Round4VerifyAndReveal: %v", err)
	}

	proof, err = bobDkg.Round5DecommitmentAndStartOt(proof)
	if err != nil {
		log.Fatalf("Error in Round5DecommitmentAndStartOt: %v", err)
	}

	compressedReceiversMaskedChoice, err := aliceDkg.Round6DkgRound2Ot(proof)
	if err != nil {
		log.Fatalf("Error in Round6DkgRound2Ot: %v", err)
	}

	challenge, err := bobDkg.Round7DkgRound3Ot(compressedReceiversMaskedChoice)
	if err != nil {
		log.Fatalf("Error in Round7DkgRound3Ot: %v", err)
	}

	challengeResponse, err := aliceDkg.Round8DkgRound4Ot(challenge)
	if err != nil {
		log.Fatalf("Error in Round8DkgRound4Ot: %v", err)
	}
	challengeOpenings, err := bobDkg.Round9DkgRound5Ot(challengeResponse)
	if err != nil {
		log.Fatalf("Error in Round9DkgRound5Ot: %v", err)
	}

	err = aliceDkg.Round10DkgRound6Ot(challengeOpenings)
	if err != nil {
		log.Fatalf("Error in Round10DkgRound6Ot: %v", err)
	}

	pkA := curve.ScalarBaseMult(aliceDkg.Output().SecretKeyShare)
	computedPublicKeyA := pkA.Mul(bobDkg.Output().SecretKeyShare)
	publicKeyBytes := computedPublicKeyA.ToAffineUncompressed()
	publicKeyUnmarshal, err := crypto.UnmarshalPubkey(publicKeyBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal public key: %v", err)
	}
	address := crypto.PubkeyToAddress(*publicKeyUnmarshal)

	fmt.Printf("pkA: %x\n", pkA.ToAffineUncompressed())
	fmt.Printf("computedPublicKeyA: %x\n", computedPublicKeyA.ToAffineUncompressed())
	fmt.Printf("publicKeyBytes: %x\n", publicKeyBytes)
	fmt.Printf("Derived address: %s\n", address.Hex())

	return aliceDkg, bobDkg, hexutil.Encode(publicKeyBytes), address
}

func full_sign(curve *curves.Curve, message []byte, aliceDkgOutput *dkg.AliceOutput, bobDkgOutput *dkg.BobOutput) *curves.EcdsaSignature {
	aliceSign := sign.NewAlice(curve, sha3.NewLegacyKeccak256(), aliceDkgOutput)
	bobSign := sign.NewBob(curve, sha3.NewLegacyKeccak256(), bobDkgOutput)

	seed, err := aliceSign.Round1GenerateRandomSeed()
	if err != nil {
		log.Fatalf("Error in Round1GenerateRandomSeed: %v", err)
	}
	round3Output, err := bobSign.Round2Initialize(seed)
	if err != nil {
		log.Fatalf("Error in Round2Initialize: %v", err)
	}
	round4Output, err := aliceSign.Round3Sign(message, round3Output)
	if err != nil {
		log.Fatalf("Error in Round3Sign: %v", err)
	}
	err = bobSign.Round4Final(message, round4Output)
	if err != nil {
		log.Fatalf("Error in Round4Final: %v", err)
	}

	return bobSign.Signature
}
func printSignedTxAsJSON(signedTx *types.Transaction) {
	signer := types.LatestSignerForChainID(signedTx.ChainId())
	from, _ := types.Sender(signer, signedTx)

	v, r, s := signedTx.RawSignatureValues()

	txJSON := struct {
		Nonce    uint64          `json:"nonce"`
		GasPrice *big.Int        `json:"gasPrice"`
		GasLimit uint64          `json:"gasLimit"`
		To       *common.Address `json:"to"`
		Value    *big.Int        `json:"value"`
		Data     hexutil.Bytes   `json:"data"`
		From     common.Address  `json:"from"`
		V        *big.Int        `json:"v"`
		R        *big.Int        `json:"r"`
		S        *big.Int        `json:"s"`
	}{
		Nonce:    signedTx.Nonce(),
		GasPrice: signedTx.GasPrice(),
		GasLimit: signedTx.Gas(),
		To:       signedTx.To(),
		Value:    signedTx.Value(),
		Data:     signedTx.Data(),
		From:     from,
		V:        v,
		R:        r,
		S:        s,
	}

	jsonData, err := json.MarshalIndent(txJSON, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal transaction to JSON: %v", err)
	}
	fmt.Printf("Signed Transaction as JSON:\n%s\n", string(jsonData))
}
