package util

import (
	"io/ioutil"
	"net/http"
	"strings"
)

func Do(api, jsonData string) ([]byte, error) {

	client := http.DefaultClient
	req, err := http.NewRequest("POST", api, strings.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	dataByte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return dataByte, nil
}
