package alicloud

import (
	"testing"
)

func TestParseRoleArn(t *testing.T) {
	arn := "acs:ram::5138828231865461:role/elk"
	result, err := parseARN(arn)
	if err != nil {
		t.Fatal(err)
	}
	if result.AccountNumber != "5138828231865461" {
		t.Fatalf("got %s but expected %s", result.AccountNumber, "5138828231865461")
	}
	if result.Type != arnTypeRole {
		t.Fatalf("got %d but expected %d", result.Type, arnTypeRole)
	}
	if result.RoleName != "elk" {
		t.Fatalf("got %s but wanted %s", result.RoleName, "elk")
	}
	if result.RoleAssumerName != "" {
		t.Fatalf("got %s but wanted %s", result.RoleAssumerName, "")
	}
}

func TestParseAssumedRoleArn(t *testing.T) {
	arn := "acs:ram::5138828231865461:assumed-role/elk/vm-ram-i-rj978rorvlg76urhqh7q"
	result, err := parseARN(arn)
	if err != nil {
		panic(err)
	}
	if result.AccountNumber != "5138828231865461" {
		t.Fatalf("got %s but expected %s", result.AccountNumber, "5138828231865461")
	}
	if result.Type != arnTypeAssumedRole {
		t.Fatalf("got %d but expected %d", result.Type, arnTypeAssumedRole)
	}
	if result.RoleName != "elk" {
		t.Fatalf("got %s but wanted %s", result.RoleName, "elk")
	}
	if result.RoleAssumerName != "vm-ram-i-rj978rorvlg76urhqh7q" {
		t.Fatalf("got %s but wanted %s", result.RoleAssumerName, "vm-ram-i-rj978rorvlg76urhqh7q")
	}
}

func TestParseEmpty(t *testing.T) {
	arn := ""
	_, err := parseARN(arn)
	if err == nil {
		t.Fatal("expected an err")
	}
}
