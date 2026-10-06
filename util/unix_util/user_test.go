package unix_util

import "testing"

func TestCredentialIncludesSupplementaryGroups(t *testing.T) {
	user := &User{Username: "device", Uid: 1001, Gid: 1002, Groups: []uint64{1002, 1003}}
	credential, err := user.credential()
	if err != nil {
		t.Fatal(err)
	}
	if credential.Uid != 1001 || credential.Gid != 1002 {
		t.Fatalf("unexpected uid/gid: %#v", credential)
	}
	if len(credential.Groups) != 2 || credential.Groups[0] != 1002 || credential.Groups[1] != 1003 {
		t.Fatalf("unexpected supplementary groups: %#v", credential.Groups)
	}
}

func TestCredentialRejectsOverflow(t *testing.T) {
	user := &User{Username: "device", Uid: uint64(^uint32(0)) + 1, Gid: 1002}
	if _, err := user.credential(); err == nil {
		t.Fatal("expected oversized uid to be rejected")
	}
}
