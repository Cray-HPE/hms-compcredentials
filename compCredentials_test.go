// MIT License
//
// (C) Copyright [2019, 2021] Hewlett Packard Enterprise Development LP
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

package compcredentials

import (
	"fmt"
	"reflect"
	sstorage "github.com/Cray-HPE/hms-securestorage"
	"testing"
)

func TestGetCompCred(t *testing.T) {
	var tests = []struct {
		xname   string
		ssInput string
		ssData  []sstorage.MockLookup
		resp    CompCredentials
		respErr bool
	}{
		{
			xname:   "x0c0s1b0",
			ssInput: "secret/hms-cred/x0c0s1b0",
			ssData: []sstorage.MockLookup{
				{
					Output: sstorage.OutputLookup{
						Output: &CompCredentials{
							Xname:    "x0c0s1b0",
							URL:      "10.4.0.21/redfish/v1/UpdateService",
							Username: "test1",
							Password: "123",
						},
						Err: nil,
					},
				},
			},
			resp: CompCredentials{
				Xname:    "x0c0s1b0",
				URL:      "10.4.0.21/redfish/v1/UpdateService",
				Username: "test1",
				Password: "123",
			},
			respErr: false,
		}, {
			xname:   "x0c0s1b0",
			ssInput: "secret/hms-cred/x0c0s1b0",
			ssData: []sstorage.MockLookup{
				{
					Output: sstorage.OutputLookup{
						Output: &CompCredentials{},
						Err:    fmt.Errorf("Cannot get secret data"),
					},
				},
			},
			resp:    CompCredentials{},
			respErr: true,
		},
	}

	ss, adapter := sstorage.NewMockAdapter()
	ccs := NewCompCredStore("secret/hms-cred", ss)
	for i, test := range tests {
		adapter.LookupNum = 0
		adapter.LookupData = test.ssData
		r, err := ccs.GetCompCred(test.xname)
		if err == nil && !test.respErr {
			if !reflect.DeepEqual(r, test.resp) {
				t.Errorf("Test %v Failed: Expected credentials %v but got %v", i, test.resp, r)
			}
			if adapter.LookupData[0].Input.Key != test.ssInput {
				t.Errorf("Test %v Failed: Expected ssKey %v but got %v", i, test.ssInput, adapter.LookupData[0].Input.Key)
			}
		} else if (err == nil) == test.respErr {
			if test.respErr {
				t.Errorf("Test %v Failed: Expected an error.", i)
			} else {
				t.Errorf("Test %v Failed: Unexpected error - %v", i, err)
			}
		}
	}
}

func TestGetAllCompCreds(t *testing.T) {
	var tests = []struct {
		ssLookupKeyPath string
		ssLookupKeys    []string
		ssLKData        []sstorage.MockLookupKeys
		ssLData         []sstorage.MockLookup
		resp            map[string]CompCredentials
		respErr         bool
	}{
		{
			ssLookupKeyPath: "secret/hms-cred",
			ssLookupKeys:    []string{"secret/hms-cred/x0c0s1b0", "secret/hms-cred/x0c0s2b0"},
			ssLKData: []sstorage.MockLookupKeys{
				{
					Output: sstorage.OutputLookupKeys{
						Klist: []string{"x0c0s1b0", "x0c0s2b0"},
						Err:   nil,
					},
				},
			},
			ssLData: []sstorage.MockLookup{
				{
					Output: sstorage.OutputLookup{
						Output: &CompCredentials{
							Xname:    "x0c0s1b0",
							URL:      "10.4.0.21/redfish/v1/UpdateService",
							Username: "test1",
							Password: "123",
						},
						Err: nil,
					},
				}, {
					Output: sstorage.OutputLookup{
						Output: &CompCredentials{
							Xname:    "x0c0s2b0",
							URL:      "10.4.0.22/redfish/v1/UpdateService",
							Username: "test2",
							Password: "456",
						},
						Err: nil,
					},
				},
			},
			resp: map[string]CompCredentials{
				"x0c0s1b0": CompCredentials{
					Xname:    "x0c0s1b0",
					URL:      "10.4.0.21/redfish/v1/UpdateService",
					Username: "test1",
					Password: "123",
				},
				"x0c0s2b0": CompCredentials{
					Xname:    "x0c0s2b0",
					URL:      "10.4.0.22/redfish/v1/UpdateService",
					Username: "test2",
					Password: "456",
				},
			},
			respErr: false,
		}, {
			ssLookupKeyPath: "secret/hms-cred",
			ssLookupKeys:    []string{"secret/hms-cred/x0c0s1b0"},
			ssLKData: []sstorage.MockLookupKeys{
				{
					Output: sstorage.OutputLookupKeys{
						Klist: []string{"x0c0s1b0"},
						Err:   nil,
					},
				},
			},
			ssLData: []sstorage.MockLookup{
				{
					Output: sstorage.OutputLookup{
						Output: &CompCredentials{},
						Err:    fmt.Errorf("Cannot get secret data"),
					},
				},
			},
			resp:    map[string]CompCredentials{},
			respErr: false,
		}, {
			ssLookupKeyPath: "secret/hms-cred",
			ssLookupKeys:    []string{},
			ssLKData: []sstorage.MockLookupKeys{
				{
					Output: sstorage.OutputLookupKeys{
						Klist: []string{},
						Err:   fmt.Errorf("Cannot get secret data"),
					},
				},
			},
			ssLData: []sstorage.MockLookup{},
			resp:    map[string]CompCredentials{},
			respErr: true,
		},
	}

	ss, adapter := sstorage.NewMockAdapter()
	ccs := NewCompCredStore("secret/hms-cred", ss)
	for i, test := range tests {
		adapter.LookupKeysNum = 0
		adapter.LookupKeysData = test.ssLKData
		adapter.LookupNum = 0
		adapter.LookupData = test.ssLData
		r, err := ccs.GetAllCompCreds()
		if err == nil && !test.respErr {
			if !reflect.DeepEqual(r, test.resp) {
				t.Errorf("Test %v Failed: Expected credentials %v but got %v", i, test.resp, r)
			}
			for j, lData := range adapter.LookupData {
				if lData.Input.Key != test.ssLookupKeys[j] {
					t.Errorf("Test %v Failed: Expected key%v to be %v but got %v", i, j, test.ssLookupKeys[j], lData.Input.Key)
				}
			}
			if adapter.LookupKeysData[0].Input.KeyPath != test.ssLookupKeyPath {
				t.Errorf("Test %v Failed: Expected ssKey %v but got %v", i, test.ssLookupKeyPath, adapter.LookupKeysData[0].Input.KeyPath)
			}
		} else if (err == nil) == test.respErr {
			if test.respErr {
				t.Errorf("Test %v Failed: Expected an error.", i)
			} else {
				t.Errorf("Test %v Failed: Unexpected error - %v", i, err)
			}
		}
	}
}

func TestGetCompCreds(t *testing.T) {
	var tests = []struct {
		xnames       []string
		ssLookupKeys []string
		ssLData      []sstorage.MockLookup
		resp         map[string]CompCredentials
		respErr      bool
	}{
		{
			xnames:       []string{"x0c0s1b0", "x0c0s2b0"},
			ssLookupKeys: []string{"secret/hms-cred/x0c0s1b0", "secret/hms-cred/x0c0s2b0"},
			ssLData: []sstorage.MockLookup{
				{
					Output: sstorage.OutputLookup{
						Output: &CompCredentials{
							Xname:    "x0c0s1b0",
							URL:      "10.4.0.21/redfish/v1/UpdateService",
							Username: "test1",
							Password: "123",
						},
						Err: nil,
					},
				}, {
					Output: sstorage.OutputLookup{
						Output: &CompCredentials{
							Xname:    "x0c0s2b0",
							URL:      "10.4.0.22/redfish/v1/UpdateService",
							Username: "test2",
							Password: "456",
						},
						Err: nil,
					},
				},
			},
			resp: map[string]CompCredentials{
				"x0c0s1b0": CompCredentials{
					Xname:    "x0c0s1b0",
					URL:      "10.4.0.21/redfish/v1/UpdateService",
					Username: "test1",
					Password: "123",
				},
				"x0c0s2b0": CompCredentials{
					Xname:    "x0c0s2b0",
					URL:      "10.4.0.22/redfish/v1/UpdateService",
					Username: "test2",
					Password: "456",
				},
			},
			respErr: false,
		}, {
			xnames:       []string{"x0c0s1b0"},
			ssLookupKeys: []string{"secret/hms-cred/x0c0s1b0"},
			ssLData: []sstorage.MockLookup{
				{
					Output: sstorage.OutputLookup{
						Output: &CompCredentials{},
						Err:    fmt.Errorf("Cannot get secret data"),
					},
				},
			},
			resp:    map[string]CompCredentials{},
			respErr: false,
		},
	}

	ss, adapter := sstorage.NewMockAdapter()
	ccs := NewCompCredStore("secret/hms-cred", ss)
	for i, test := range tests {
		adapter.LookupNum = 0
		adapter.LookupData = test.ssLData
		r, err := ccs.GetCompCreds(test.xnames)
		if err == nil && !test.respErr {
			if !reflect.DeepEqual(r, test.resp) {
				t.Errorf("Test %v Failed: Expected credentials %v but got %v", i, test.resp, r)
			}
			for j, lData := range adapter.LookupData {
				if lData.Input.Key != test.ssLookupKeys[j] {
					t.Errorf("Test %v Failed: Expected key%v to be %v but got %v", i, j, test.ssLookupKeys[j], lData.Input.Key)
				}
			}
		} else if (err == nil) == test.respErr {
			if test.respErr {
				t.Errorf("Test %v Failed: Expected an error.", i)
			} else {
				t.Errorf("Test %v Failed: Unexpected error - %v", i, err)
			}
		}
	}
}

func TestStoreCompCred(t *testing.T) {
	var tests = []struct {
		in      CompCredentials
		ssInput string
		ssData  []sstorage.MockStore
		respErr bool
	}{
		{
			in: CompCredentials{
				Xname:    "x0c0s1b0",
				URL:      "10.4.0.21/redfish/v1/UpdateService",
				Username: "test1",
				Password: "123",
			},
			ssInput: "secret/hms-cred/x0c0s1b0",
			ssData: []sstorage.MockStore{
				{
					Output: sstorage.OutputStore{
						Err: nil,
					},
				},
			},
			respErr: false,
		}, {
			in: CompCredentials{
				Xname:    "x0c0s1b0",
				URL:      "10.4.0.21/redfish/v1/UpdateService",
				Username: "test1",
				Password: "123",
			},
			ssInput: "secret/hms-cred/x0c0s1b0",
			ssData: []sstorage.MockStore{
				{
					Output: sstorage.OutputStore{
						Err: fmt.Errorf("Cannot get secret data"),
					},
				},
			},
			respErr: true,
		},
	}

	ss, adapter := sstorage.NewMockAdapter()
	ccs := NewCompCredStore("secret/hms-cred", ss)
	for i, test := range tests {
		adapter.StoreNum = 0
		adapter.StoreData = test.ssData
		err := ccs.StoreCompCred(test.in)
		if err == nil && !test.respErr {
			if adapter.StoreData[0].Input.Key != test.ssInput {
				t.Errorf("Test %v Failed: Expected ssKey %v but got %v", i, test.ssInput, adapter.StoreData[0].Input.Key)
			}
		} else if (err == nil) == test.respErr {
			if test.respErr {
				t.Errorf("Test %v Failed: Expected an error.", i)
			} else {
				t.Errorf("Test %v Failed: Unexpected error - %v", i, err)
			}
		}
	}
}
