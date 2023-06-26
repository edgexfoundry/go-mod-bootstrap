package file

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/edgexfoundry/go-mod-bootstrap/v3/bootstrap/interfaces"
)

func Load(path string, timeout time.Duration, provider interfaces.SecretProvider) ([]byte, error) {
	var fileBytes []byte
	var err error

	parsedUrl, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("Could not parse file path: %v", err)
	}

	if (parsedUrl.Scheme == "http" || parsedUrl.Scheme == "https") {
		client := &http.Client{
			Timeout: timeout,
		}
		req, err := http.NewRequest("GET", path, nil)

		// Get httpheader secret
		params := parsedUrl.Query()
		edgexSecretName := params.Get("edgexSecretName")
		if edgexSecretName != "" {
			secrets, err := provider.GetSecret(edgexSecretName)
			if err != nil {
				return nil, err
			}

			// Set request header
			if len(secrets) > 0 && secrets["type"] == "httpheader" {
				if secrets["headername"] != "" && secrets["headercontents"] != "" {
					req.Header.Add(secrets["headername"], secrets["headercontents"])
				} else {
					return nil, fmt.Errorf("Secret headername and headercontents can not be empty")
				}
			} else {
				return nil, fmt.Errorf("Secret type is not httpheader")
			}
		}

		// Run request
		resp, err := client.Do(req)

		if err != nil {
			return nil, fmt.Errorf("Could not get remote file: %s", parsedUrl.Redacted())
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("Invalid status code %d loading remote file: %s", resp.StatusCode, parsedUrl.Redacted())
		}

		fileBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("Could not read remote file: : %s", parsedUrl.Redacted())
		}
	} else {
		fileBytes, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("Could not read file %s: %v", path, err)
		}
	}

	return fileBytes, nil
}
