package main

import (
	"coinbase_tecdsa_2/lib/eth"
	"context"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/sign"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

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

	curve := curves.K256()
	// generate dkg
	aliceDkg, bobDkg, _, address := full_dkg(curve)

	// message := []byte("hello world")
	// signature := full_sign(curve, message, aliceDkg, bobDkg)
	// fmt.Println("signature: ", signature)

	rlpEncodedTx := generateRlpEncodedTx(
		*client,
		address,
		common.HexToAddress("0x1139F74a15f25f7503B30cd36D527DA5A6D3E15D"),
	)
	signature := full_sign(curve, rlpEncodedTx, aliceDkg, bobDkg)
	fmt.Println("signature: ", signature)

	// verify
	digest := crypto.Keccak256(rlpEncodedTx)
	unCompressedAffinePublicKey := aliceDkg.Output().PublicKey.ToAffineUncompressed()
	x := new(big.Int).SetBytes(unCompressedAffinePublicKey[1:33])
	y := new(big.Int).SetBytes(unCompressedAffinePublicKey[33:])

	// 디버깅을 위해 X, Y 좌표 출력
	fmt.Printf("X: %s\n", x.String())
	fmt.Printf("Y: %s\n", y.String())

	ecCurve, _ := curve.ToEllipticCurve()
	publicKey := &curves.EcPoint{
		Curve: ecCurve,
		X:     x,
		Y:     y,
	}
	fmt.Printf("Public Key: X = %s, Y = %s\n", publicKey.X.String(), publicKey.Y.String())
	fmt.Printf("Digest: %x\n", digest)
	fmt.Printf("Signature: R = %s, S = %s\n", signature.R.String(), signature.S.String())

	signatureBytes := append(signature.R.Bytes(), signature.S.Bytes()...)
	isVerifiedByGoEthereum := crypto.VerifySignature(publicKey.Bytes(), digest, signatureBytes)
	fmt.Println("is Verify by go-ethereum:", isVerifiedByGoEthereum)

	// kryptology 라이브러리로 서명 검증
	isVerifiedByKryptology := curves.VerifyEcdsa(publicKey, digest, signature)
	fmt.Println("is Verify by kryptology:", isVerifiedByKryptology)
}

func generateRlpEncodedTx(client ethclient.Client, fromAddress common.Address, toAddress common.Address) []byte {
	// sign
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("failed to get nonce: %v", err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("failed to get gas price: %v", err)
	}
	testAmount := big.NewInt(100000000000000) // 0.0001 Ether

	gasLimit := uint64(21000)
	tx := eth.GenerateTransaction(nonce, toAddress, testAmount, gasLimit, gasPrice, nil)

	rlpEncodedTx, _ := tx.MarshalBinary()
	fmt.Println("rlpEncodedTx: ", rlpEncodedTx)
	fmt.Println("common.Bytes2Hex(rlpEncodedTx): ", common.Bytes2Hex(rlpEncodedTx))
	return rlpEncodedTx
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

	// 퍼블릭 키로부터 이더리움 주소 생성
	publicKeyBytes := computedPublicKeyA.ToAffineUncompressed()
	publicKeyUnmarshal, _ := crypto.UnmarshalPubkey(publicKeyBytes)
	publicKeyHex := hexutil.Encode(publicKeyBytes)
	address := crypto.PubkeyToAddress(*publicKeyUnmarshal)
	fmt.Println("pubkeybytes: ", publicKeyHex)
	fmt.Println("address: ", address)

	return aliceDkg, bobDkg, publicKeyHex, address
}

func full_sign(curve *curves.Curve, message []byte, aliceDkg *dkg.Alice, bobDkg *dkg.Bob) *curves.EcdsaSignature {
	aliceSign := sign.NewAlice(curve, sha3.NewLegacyKeccak256(), aliceDkg.Output())
	bobSign := sign.NewBob(curve, sha3.NewLegacyKeccak256(), bobDkg.Output())

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
