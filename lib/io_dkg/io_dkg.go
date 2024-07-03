// iodkg/dkg_io.go

package iodkg

import (
	"encoding/json"
	"io/ioutil"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/ethereum/go-ethereum/common"
)

type DkgData struct {
	AliceOutput dkg.AliceOutput
	BobOutput   dkg.BobOutput
	Address     string
}

// SaveDkgData saves the essential DKG data to a file
func SaveDkgData(aliceDkg *dkg.Alice, bobDkg *dkg.Bob, address common.Address, filename string) error {
	data := DkgData{
		AliceOutput: *aliceDkg.Output(),
		BobOutput:   *bobDkg.Output(),
		Address:     address.Hex(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filename, jsonData, 0644)
}

// LoadDkgData loads the essential DKG data from a file
func LoadDkgData(filename string, curve *curves.Curve) (*dkg.AliceOutput, *dkg.BobOutput, common.Address, error) {
	jsonData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, common.Address{}, err
	}

	var data DkgData
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return nil, nil, common.Address{}, err
	}

	address := common.HexToAddress(data.Address)

	return &data.AliceOutput, &data.BobOutput, address, nil
}
