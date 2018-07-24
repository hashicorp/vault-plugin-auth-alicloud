package ali

import (
	"testing"
)

// This test ensures we're getting what we expect for the STS endpoint
// as versions of the Aliyun SDK change going forward. If it fails, the code
// in getSTSEndpoint retrieving this information needs to be updated to account for
// any new or changed endpoints.
func TestSTSEndpointRetrievingCorrectly(t *testing.T) {
	if _, err := getSTSEndpoint(); err != nil {
		t.Fatal(err)
	}
}
